//! Commit blob plaintext `[Header, signature, [Section*]]` and its opened form, the commit's
//! held parts (spec/wire.md §4).
//!
//! Confidentiality invariants (spec/wire.md §4, spec/sync.md §3):
//! - a section holds the parts of one reader actor, sealed under a fresh random section key
//!   that encrypts this one plaintext (nonce zero, used once) and nothing else ever: a rewrite
//!   seals the section again under a new key;
//! - the section key is wrapped under `kdf("section", read secret)` of that actor with a random
//!   nonce carried in the wrap (`osis_crypto::wrap_section`), so two wraps of one commit's
//!   section under one read secret never share a nonce;
//! - both AEADs take the commit ID as AD, so a section opens only inside its own commit;
//! - a reader that cannot open a section learns its `ai` list, its thing's owner chain and its
//!   size, nothing else, and copies it verbatim into a fresh encryption (`seal_commit`'s
//!   `extra`).

use crate::cbor::{as_idx, as_list, strictly_ascending, uidx};
use crate::header::{Header, LIMITS};
use crate::Error;
use osis_base::cbor::{MAJOR_ARRAY, MAJOR_UINT, encode_into, head};
use osis_base::{CommitId, CreationRecord, Tid, Value};
use osis_crypto::{CryptoRngCore, SECTION_WRAP_LEN, Secret32, Signature};
use std::collections::BTreeMap;

/// One delta of a commit blob: its aspect's index, canonical delta (or snapshot) bytes, and the creation records an ephemeral commit carries beside it
/// (spec/commits.md §2): sorted by tid, distinct; none in a durable commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub ai: usize,
    pub delta: Vec<u8>,
    pub records: Vec<CreationRecord>,
}

impl Part {
    /// A part carrying no records.
    pub fn new(ai: usize, delta: Vec<u8>) -> Part {
        Part { ai, delta, records: Vec::new() }
    }
}

/// A commit as a node holds it: the header, the signature and the parts it opened (its stored
/// form, `[Header, signature, [Part*]]`; an inbox blob's payload too, spec/wire.md §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBlob {
    pub header: Header,
    pub signature: Signature,
    /// Sorted by `ai`, distinct.
    pub parts: Vec<Part>,
}

impl CommitBlob {
    pub fn id(&self) -> CommitId {
        self.header.id()
    }

    /// Canonical bytes of the opened form (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, MAJOR_ARRAY, 3);
        out.extend_from_slice(&self.header.encode());
        encode_into(&self.signature.to_value(), &mut out);
        encode_parts(&self.parts, &mut out);
        out
    }

    /// Decodes the opened form. Linked header lists stay unresolved; part indices are checked
    /// against the header by [`crate::verify_part`].
    pub fn decode(b: &[u8]) -> Result<CommitBlob, Error> {
        Self::decode_as(b, false)
    }

    /// `decode` of a commit this node stored, checked when it arrived: its delete keys are not
    /// decompressed again (a third of what re-reading an aspect's bodies cost). Only for bytes
    /// this node wrote from a blob `decode` accepted (stored and pending rows: a parked row of
    /// raw bytes fails here as there, on its version); never for bytes from a peer or a bundle.
    pub fn decode_stored(b: &[u8]) -> Result<CommitBlob, Error> {
        Self::decode_as(b, true)
    }

    fn decode_as(b: &[u8], stored: bool) -> Result<CommitBlob, Error> {
        let v = osis_base::decode(b, &LIMITS)?;
        let [hv, sv, pv] = as_list(&v)? else { return Err(Error::Malformed("commit blob arity")) };
        let header = if stored { Header::from_stored_value(hv)? } else { Header::from_value(hv)? };
        let signature = Signature::from_value(sv)?;
        let parts = decode_parts(pv, header.ephemeral.is_some())?;
        let blob = CommitBlob { header, signature, parts };
        if blob.encode() != b {
            return Err(Error::Malformed("commit blob not canonical"));
        }
        Ok(blob)
    }

    /// Aspects whose delta this blob does not hold (purged, or in a section not opened).
    pub fn missing(&self) -> Vec<usize> {
        (0..self.header.aspects.len()).filter(|ai| self.parts.binary_search_by_key(ai, |p| p.ai).is_err()).collect()
    }
}

/// `[Part*]` (a part `[ai, delta, [creation*]]`) by concatenation: delta bytes are already
/// canonical items.
fn encode_parts(parts: &[Part], out: &mut Vec<u8>) {
    head(out, MAJOR_ARRAY, parts.len() as u64);
    for p in parts {
        head(out, MAJOR_ARRAY, 3);
        head(out, MAJOR_UINT, p.ai as u64);
        out.extend_from_slice(&p.delta);
        encode_into(&records_value(&p.records), out);
    }
}

/// Encoded length of one part.
pub(crate) fn part_len(p: &Part) -> usize {
    use osis_base::cbor::head_len;
    (head_len(3) + head_len(p.ai as u64)).saturating_add(p.delta.len()).saturating_add(osis_base::encode(&records_value(&p.records)).len())
}

/// The parts of a `[Part*]` value: sorted by `ai`, distinct; records only beside an
/// ephemeral commit's delta.
fn decode_parts(pv: &Value, ephemeral: bool) -> Result<Vec<Part>, Error> {
    let mut parts = Vec::new();
    for p in as_list(pv)? {
        let [ai, d, rs] = as_list(p)? else { return Err(Error::Malformed("part arity")) };
        if !matches!(d, Value::List(_)) {
            return Err(Error::Malformed("part delta"));
        }
        let records = as_list(rs)?.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("creation record"))).collect::<Result<Vec<_>, _>>()?;
        if !strictly_ascending(&records, CreationRecord::tid) {
            return Err(Error::Malformed("part records not sorted and distinct"));
        }
        if !records.is_empty() && !ephemeral {
            return Err(Error::Invalid("creation records beside a durable commit's delta"));
        }
        parts.push(Part { ai: as_idx(ai)?, delta: osis_base::encode(d), records });
    }
    if !strictly_ascending(&parts, |p| p.ai) {
        return Err(Error::Malformed("parts not sorted and distinct"));
    }
    Ok(parts)
}

/// The records list of a part.
pub(crate) fn records_value(rs: &[CreationRecord]) -> Value {
    Value::List(rs.iter().map(CreationRecord::to_value).collect())
}

/// One section of a commit blob `[[ai*], [owner*], wrap, ciphertext]` (spec/wire.md §4): the
/// aspect indices of its parts (ascending, distinct, each with a part inside), the owner chain
/// of their thing up to the actor its read secret derives from (a reader derives the secret
/// through it without the thing's record), the section key wrapped under that read secret,
/// the parts sealed under that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub ais: Vec<usize>,
    pub owners: Vec<Tid>,
    pub wrap: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Section {
    /// Encoded length.
    pub fn len(&self) -> usize {
        use osis_base::cbor::head_len;
        let ais = head_len(self.ais.len() as u64) + self.ais.iter().map(|a| head_len(*a as u64)).sum::<usize>();
        let owners = head_len(self.owners.len() as u64) + self.owners.len() * (1 + osis_base::format::TID_LEN);
        head_len(4) + ais + owners + head_len(self.wrap.len() as u64) + self.wrap.len() + head_len(self.ciphertext.len() as u64) + self.ciphertext.len()
    }

    /// Never empty; for clippy's `len` convention.
    pub fn is_empty(&self) -> bool {
        false
    }

    fn to_value(&self) -> Value {
        Value::List(vec![Value::List(self.ais.iter().map(|a| uidx(*a)).collect()), Value::List(self.owners.iter().map(crate::cbor::tid).collect()), Value::bytes(&self.wrap), Value::bytes(&self.ciphertext)])
    }

    fn from_value(v: &Value) -> Result<Section, Error> {
        let [ais, owners, wrap, ct] = as_list(v)? else { return Err(Error::Malformed("section arity")) };
        let ais = as_list(ais)?.iter().map(as_idx).collect::<Result<Vec<_>, _>>()?;
        if ais.is_empty() || !strictly_ascending(&ais, |a| *a) {
            return Err(Error::Malformed("section aspects not ascending and distinct"));
        }
        let owners = as_list(owners)?.iter().map(crate::cbor::as_tid).collect::<Result<Vec<_>, _>>()?;
        if owners.len() > osis_base::format::MAX_OWNER_DEPTH {
            return Err(Error::Malformed("section owner chain too deep"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if !owners.iter().all(|o| seen.insert(*o)) {
            return Err(Error::Malformed("section owner chain repeats a thing"));
        }
        let wrap = wrap.as_bytes().ok_or(Error::Malformed("section wrap"))?.to_vec();
        if wrap.len() != SECTION_WRAP_LEN {
            return Err(Error::Malformed("section wrap length"));
        }
        let ciphertext = ct.as_bytes().ok_or(Error::Malformed("section ciphertext"))?.to_vec();
        Ok(Section { ais, owners, wrap, ciphertext })
    }

    /// Whether `key` may be this section's key, judged by its first plaintext bytes alone (an
    /// array of parts, each a 3-array; `encode_parts`), NOT authenticated: forensic tests only,
    /// to rule a candidate out before `open_section`'s pass over the whole ciphertext. Never
    /// false for the section's own key.
    #[doc(hidden)]
    pub fn may_open_with(&self, key: &[u8; 32]) -> bool {
        let at = |i| osis_crypto::aead::plain_byte(key, &osis_crypto::aead::ZERO_NONCE, &self.ciphertext, i);
        let Some(b0) = at(0) else { return false };
        // an empty array, or a count past one byte's head, leaves byte 1 unknown
        b0 >> 5 == MAJOR_ARRAY && (b0 == MAJOR_ARRAY << 5 || b0 & 0x1f >= 24 || at(1) == Some(MAJOR_ARRAY << 5 | 3))
    }

    /// Opens this section with one of `secrets` (newest first): the parts inside, which must
    /// be exactly on the aspects listed. `None`: no secret opens the wrap. A section that opens
    /// to parts disagreeing with its list is bad input.
    pub fn open(&self, commit: &CommitId, ephemeral: bool, secrets: &[Secret32]) -> Result<Option<Vec<Part>>, Error> {
        let Some(key) = secrets.iter().find_map(|s| osis_crypto::unwrap_section(s, commit, &self.wrap).ok()) else { return Ok(None) };
        let pt = osis_crypto::open_section(commit, &key, &self.ciphertext)?;
        let v = osis_base::decode(&pt, &LIMITS)?;
        let parts = decode_parts(&v, ephemeral)?;
        if !parts.iter().map(|p| p.ai).eq(self.ais.iter().copied()) {
            return Err(Error::Malformed("section parts disagree with its aspect list"));
        }
        let mut canon = Vec::new();
        encode_parts(&parts, &mut canon);
        if canon != pt {
            return Err(Error::Malformed("section not canonical"));
        }
        Ok(Some(parts))
    }

    /// Seals `parts` (sorted) under the read secret `secret` of their thing, listing its owner
    /// chain `owners`.
    pub fn seal(commit: &CommitId, parts: &[Part], owners: Vec<Tid>, secret: &Secret32, rng: &mut dyn CryptoRngCore) -> Result<Section, Error> {
        let mut pt = Vec::new();
        encode_parts(parts, &mut pt);
        let (key, ciphertext) = osis_crypto::seal_section(commit, &pt, rng)?;
        let wrap = osis_crypto::wrap_section(secret, commit, &key, rng)?.to_vec();
        let ais: Vec<usize> = parts.iter().map(|p| p.ai).collect();
        Ok(Section { ais, owners, wrap, ciphertext })
    }
}

/// A commit blob's plaintext as the wire carries it: header, signature, sections sorted by
/// their first aspect index, no aspect in two sections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub header: Header,
    pub signature: Signature,
    pub sections: Vec<Section>,
}

impl Envelope {
    pub fn id(&self) -> CommitId {
        self.header.id()
    }

    /// Canonical plaintext bytes (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, MAJOR_ARRAY, 3);
        out.extend_from_slice(&self.header.encode());
        encode_into(&self.signature.to_value(), &mut out);
        encode_into(&Value::List(self.sections.iter().map(Section::to_value).collect()), &mut out);
        out
    }

    /// Decodes a commit blob plaintext. Linked header lists stay unresolved; aspect indices
    /// are checked against the header once resolved (`prefix_groups`).
    pub fn decode(b: &[u8]) -> Result<Envelope, Error> {
        let v = osis_base::decode(b, &LIMITS)?;
        let [hv, sv, ss] = as_list(&v)? else { return Err(Error::Malformed("commit blob arity")) };
        let header = Header::from_value(hv)?;
        let signature = Signature::from_value(sv)?;
        let sections = as_list(ss)?.iter().map(Section::from_value).collect::<Result<Vec<_>, _>>()?;
        if !strictly_ascending(&sections, |s| s.ais.first().copied()) {
            return Err(Error::Malformed("sections not sorted by first aspect"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if sections.iter().flat_map(|s| s.ais.iter()).any(|a| !seen.insert(*a)) {
            return Err(Error::Malformed("an aspect in two sections"));
        }
        let e = Envelope { header, signature, sections };
        if e.encode() != b {
            return Err(Error::Malformed("commit blob not canonical"));
        }
        Ok(e)
    }

    /// Every aspect index any section lists, ascending.
    pub fn ais(&self) -> Vec<usize> {
        self.sections.iter().flat_map(|s| s.ais.iter().copied()).collect()
    }

    /// Opens every section `secrets` has a read secret for (asked per section): the commit with
    /// the parts opened, and the sections left sealed.
    pub fn open(&self, mut secrets: impl FnMut(&Section) -> Vec<Secret32>) -> Result<Opened, Error> {
        let id = self.id();
        let ephemeral = self.header.ephemeral.is_some();
        let mut parts = Vec::new();
        let mut sealed = Vec::new();
        for s in &self.sections {
            match s.open(&id, ephemeral, &secrets(s))? {
                Some(ps) => parts.extend(ps),
                None => sealed.push(s.clone()),
            }
        }
        parts.sort_by_key(|p| p.ai);
        Ok(Opened { commit: CommitBlob { header: self.header.clone(), signature: self.signature, parts }, sealed })
    }
}

/// What opening an envelope gives: the commit with its opened parts, and the sections no held
/// secret opened (copied verbatim into a fresh encryption).
#[derive(Clone, Debug)]
pub struct Opened {
    pub commit: CommitBlob,
    pub sealed: Vec<Section>,
}

/// Seals a commit's parts into sections, one per value of `section_of(ai)` (the aspect's
/// thing), each wrapped under the read secret `secret_of(key, parts)` gives with the thing's
/// owner chain (that secret at the epoch the writer uses, spec/crypto.md §5); a section whose
/// secret is not held (`None`) is left out, its parts travelling in other copies; `extra`
/// sections are copied verbatim, except one listing an aspect a sealed part is on.
pub fn seal_commit<K: Ord + Clone>(c: &CommitBlob, section_of: impl Fn(usize) -> K, mut secret_of: impl FnMut(&K, &[usize]) -> Option<(Secret32, Vec<Tid>)>, extra: &[Section], rng: &mut dyn CryptoRngCore) -> Result<Envelope, Error> {
    let id = c.id();
    let mut by: BTreeMap<K, Vec<&Part>> = BTreeMap::new();
    for p in &c.parts {
        by.entry(section_of(p.ai)).or_default().push(p);
    }
    let mut sections = Vec::with_capacity(by.len() + extra.len());
    let mut own: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (k, ps) in by {
        let ais: Vec<usize> = ps.iter().map(|p| p.ai).collect();
        let Some((secret, owners)) = secret_of(&k, &ais) else { continue };
        own.extend(ais.iter().copied());
        let owned: Vec<Part> = ps.into_iter().cloned().collect();
        sections.push(Section::seal(&id, &owned, owners, &secret, rng)?);
    }
    let mut seen = own.clone();
    for s in extra {
        if s.ais.iter().any(|a| own.contains(a)) {
            continue;
        }
        if s.ais.iter().any(|a| !seen.insert(*a)) {
            return Err(Error::Malformed("an aspect in two sections"));
        }
        sections.push(s.clone());
    }
    sections.sort_by_key(|s| s.ais.first().copied());
    Ok(Envelope { header: c.header.clone(), signature: c.signature, sections })
}
