//! Commit blob plaintext `[Header, signature, [Part*]]` (spec/wire.md §4).

use crate::cbor::{array_head, as_idx, as_list, strictly_ascending, uidx};
use crate::header::{Header, LIMITS};
use crate::Error;
use osis_base::{CommitId, Value};
use osis_crypto::Signature;

/// One delta of a commit blob: aspect index, index into that aspect's hashes, canonical delta
/// (or snapshot) bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub ai: usize,
    pub di: usize,
    pub delta: Vec<u8>,
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
            let [ai, di, d] = as_list(p)? else { return Err(Error::Malformed("part arity")) };
            if !matches!(d, Value::List(_)) {
                return Err(Error::Malformed("part delta"));
            }
            parts.push(Part { ai: as_idx(ai)?, di: as_idx(di)?, delta: osis_base::encode(d) });
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

/// `[Header, signature, [Part*]]` by concatenation: header bytes and delta bytes are already
/// canonical items.
pub(crate) fn encode_parts<'a>(header: &[u8], sig: &Signature, parts: impl ExactSizeIterator<Item = &'a Part>) -> Vec<u8> {
    let mut out = Vec::new();
    array_head(3, &mut out);
    out.extend_from_slice(header);
    osis_base::cbor::encode_into(&sig.to_value(), &mut out);
    array_head(parts.len(), &mut out);
    for p in parts {
        array_head(3, &mut out);
        osis_base::cbor::encode_into(&uidx(p.ai), &mut out);
        osis_base::cbor::encode_into(&uidx(p.di), &mut out);
        out.extend_from_slice(&p.delta);
    }
    out
}
