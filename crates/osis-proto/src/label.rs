//! The label objects the protocol checks: steps and claim sets (spec/wire.md §8), the blob
//! clear prefix (§5), and the stamp, deposit, delete and signal-publish digests (§9, §11.2).
//! The one module coupled to osis-label: switch to its types when that crate lands.

use crate::Error;
use crate::dec::{self, Fields, b, opt_v};
use crate::msg::{Pk, Sig, Wrap};
use osis_core::format::{BLOB_FRAMING_VERSION, MAX_CLAIMS, MAX_COMMITMENTS, MAX_VALUE_DEPTH};
use osis_core::{BlobId, LabelId, Limits, Value, cbor, hash::hash};
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey};
use std::collections::BTreeMap;

/// A parsed registration step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepInfo {
    /// Its canonical bytes.
    pub bytes: Vec<u8>,
    /// Step ID = BLAKE3 of the bytes.
    pub id: [u8; 32],
    pub label: LabelId,
    pub prev: Option<[u8; 32]>,
    pub sync: Pk,
    pub write: Pk,
    pub delete: Pk,
    pub deposit: Pk,
    pub step_key: [u8; 32],
    pub claims_hash: [u8; 32],
    pub sig: Sig,
}

/// A label role key carried by a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKey {
    Sync,
    Write,
    Delete,
    Deposit,
}

/// The first eight items of a step (the signed part).
fn unsigned(label: &LabelId, prev: Option<&[u8; 32]>, keys: [&[u8; 32]; 5], claims_hash: &[u8; 32]) -> Vec<Value> {
    let mut v = vec![b(&label.0), opt_v(prev.map(|p| b(p)))];
    v.extend(keys.iter().map(|k| b(*k)));
    v.push(b(claims_hash));
    v
}

impl StepInfo {
    pub fn parse(bytes: &[u8]) -> Result<StepInfo, Error> {
        let v = cbor::decode(bytes, &Limits { max_depth: 2, max_bytes: bytes.len() })?;
        let mut f = Fields::exact(v, 9, "step")?;
        let label = LabelId(f.fixed()?);
        let prev = f.opt()?.map(|v| dec::fixed(v, "step prev")).transpose()?;
        let s = StepInfo {
            bytes: bytes.to_vec(),
            id: hash(bytes),
            label,
            prev,
            sync: f.fixed()?,
            write: f.fixed()?,
            delete: f.fixed()?,
            deposit: f.fixed()?,
            step_key: f.fixed()?,
            claims_hash: f.fixed()?,
            sig: f.fixed()?,
        };
        f.end()?;
        Ok(s)
    }

    /// Digest of the first eight items, signed under `"osis v1 label register"`.
    pub fn signed_digest(&self) -> [u8; 32] {
        let keys = [&self.sync, &self.write, &self.delete, &self.deposit, &self.step_key];
        hash(&cbor::encode(&Value::List(unsigned(&self.label, self.prev.as_ref(), keys, &self.claims_hash))))
    }

    /// Whether `delete_pk` (the parent's delete key; a genesis step's own) signed this step.
    pub fn signed_by(&self, delete_pk: &Pk) -> bool {
        verify(delete_pk, Domain::LabelRegister, &self.signed_digest(), &self.sig)
    }

    /// A genesis step: no `prev`, its delete key hashes to the label ID and signed it.
    pub fn is_valid_genesis(&self) -> bool {
        self.prev.is_none() && VerifyingKey::from_bytes(&self.delete).is_ok_and(|k| osis_crypto::label_id(&k) == self.label) && self.signed_by(&self.delete)
    }

    /// Whether `child` is a valid child of this step.
    pub fn is_parent_of(&self, child: &StepInfo) -> bool {
        child.label == self.label && child.prev == Some(self.id) && child.signed_by(&self.delete)
    }

    pub fn key(&self, k: StepKey) -> &Pk {
        match k {
            StepKey::Sync => &self.sync,
            StepKey::Write => &self.write,
            StepKey::Delete => &self.delete,
            StepKey::Deposit => &self.deposit,
        }
    }
}

/// The public half of a step, signed by `signer` (the parent's delete key, or its own for a
/// genesis step).
pub struct NewStep<'a> {
    pub label: LabelId,
    pub prev: Option<[u8; 32]>,
    pub sync: Pk,
    pub write: Pk,
    pub delete: Pk,
    pub deposit: Pk,
    pub step_key: [u8; 32],
    pub claims_hash: [u8; 32],
    pub signer: &'a SigningSecret,
}

impl NewStep<'_> {
    /// Canonical `Step` bytes.
    pub fn sign(&self) -> Vec<u8> {
        let keys = [&self.sync, &self.write, &self.delete, &self.deposit, &self.step_key];
        let mut items = unsigned(&self.label, self.prev.as_ref(), keys, &self.claims_hash);
        let sig = self.signer.sign(Domain::LabelRegister, &hash(&cbor::encode(&Value::List(items.clone()))));
        items.push(b(&sig.0));
        cbor::encode(&Value::List(items))
    }
}

/// A parsed claim set: claim keys and static entries, and entry boxes by static entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSet {
    pub claims: Vec<[u8; 32]>,
    /// Canonical bytes of each entry box value.
    pub boxes: BTreeMap<[u8; 32], Vec<u8>>,
}

impl ClaimSet {
    /// `ClaimSet := [[claim+], {entry: box}]`: a power-of-two count up to `MAX_CLAIMS`, every map
    /// key among the claims.
    pub fn parse(bytes: &[u8]) -> Result<ClaimSet, Error> {
        let v = cbor::decode(bytes, &Limits { max_depth: 2 + MAX_VALUE_DEPTH, max_bytes: bytes.len() })?;
        let mut f = Fields::exact(v, 2, "claim set")?;
        let claims = f
            .list(1, MAX_CLAIMS, "claims")?
            .into_iter()
            .map(|c| dec::fixed(c, "claim"))
            .collect::<Result<Vec<[u8; 32]>, _>>()?;
        if !claims.len().is_power_of_two() {
            return Err(Error::Malformed("claim count"));
        }
        let Value::Map(m) = f.next()? else { return Err(Error::Malformed("entry boxes")) };
        let mut boxes = BTreeMap::new();
        for (k, v) in m {
            let k: [u8; 32] = dec::fixed(k, "entry box key")?;
            if !claims.contains(&k) {
                return Err(Error::Malformed("entry box key"));
            }
            boxes.insert(k, cbor::encode(&v));
        }
        f.end()?;
        Ok(ClaimSet { claims, boxes })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut m = BTreeMap::new();
        for (k, v) in &self.boxes {
            m.insert(b(k), cbor::decode(v, &Limits::DEFAULT)?);
        }
        Ok(cbor::encode(&Value::List(vec![Value::List(self.claims.iter().map(|c| b(c)).collect()), Value::Map(m)])))
    }
}

/// The clear prefix fields a blind node reads (spec/wire.md §5). A blob of unknown framing version
/// has no expiry and no commitments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prefix {
    pub salt: [u8; 16],
    pub expiry: Option<u64>,
    pub commitments: Vec<[u8; 17]>,
}

pub fn prefix(blob: &[u8]) -> Result<Prefix, Error> {
    let Some((&version, rest)) = blob.split_first() else { return Err(Error::Malformed("blob prefix")) };
    if version != BLOB_FRAMING_VERSION {
        return Ok(Prefix::default());
    }
    let bad = Error::Malformed("blob prefix");
    let salt: [u8; 16] = rest.get(..16).and_then(|s| s.try_into().ok()).ok_or(bad)?;
    let expiry = u64::from_le_bytes(rest.get(16..24).and_then(|s| s.try_into().ok()).ok_or(bad)?);
    let n = *rest.get(24).ok_or(bad)? as usize;
    if n > MAX_COMMITMENTS {
        return Err(bad);
    }
    let body = rest.get(25..25 + 17 * n).ok_or(bad)?;
    let commitments: Vec<[u8; 17]> = body.as_chunks::<17>().0.to_vec();
    if !commitments.is_sorted_by(|a, b| a < b) {
        return Err(bad);
    }
    Ok(Prefix { salt, expiry: (expiry != 0).then_some(expiry), commitments })
}

fn digest3(label: &LabelId, blob_id: &BlobId, wrap: &Wrap) -> [u8; 32] {
    hash(&cbor::encode(&Value::List(vec![b(&label.0), b(&blob_id.0), b(wrap)])))
}

/// Stamp, deposit and signal-publish digest: BLAKE3(canonical `[label_id, blob_id, wrap]`).
pub fn entry_digest(label: &LabelId, blob_id: &BlobId, wrap: &Wrap) -> [u8; 32] {
    digest3(label, blob_id, wrap)
}

/// Delete digest: BLAKE3(canonical `[label_id, blob_id, Opt(at), Opt(token)]`).
pub fn delete_digest(label: &LabelId, blob_id: &BlobId, at: Option<u64>, token: Option<&[u8; 32]>) -> [u8; 32] {
    hash(&cbor::encode(&Value::List(vec![b(&label.0), b(&blob_id.0), opt_v(at.map(dec::u)), opt_v(token.map(|t| b(t)))])))
}

/// Raw Ed25519 verification under a domain.
pub fn verify(pk: &Pk, domain: Domain, digest: &[u8; 32], sig: &Sig) -> bool {
    VerifyingKey::from_bytes(pk).is_ok_and(|k| k.verify(domain, digest, &Signature(*sig)).is_ok())
}

/// Signs `digest` under `domain`, as raw bytes.
pub fn sign(key: &SigningSecret, domain: Domain, digest: &[u8; 32]) -> Sig {
    key.sign(domain, digest).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::Secret32;

    fn key(b: u8) -> SigningSecret {
        SigningSecret::from_seed(&Secret32::from_bytes([b; 32]))
    }

    // spec/wire.md §8: genesis signed by its own delete key, label ID from it; child by the parent's
    #[test]
    fn steps() {
        let del = key(3);
        let label = osis_crypto::label_id(&del.verifying_key());
        let mk = |prev, signer: &SigningSecret, delete: Pk| {
            NewStep { label, prev, sync: [1; 32], write: [2; 32], delete, deposit: [4; 32], step_key: [5; 32], claims_hash: [6; 32], signer }.sign()
        };
        let g = StepInfo::parse(&mk(None, &del, del.verifying_key().to_bytes())).unwrap();
        assert!(g.is_valid_genesis());
        assert_eq!(g.bytes.len(), crate::msg::MAX_STEP_BYTES - 34);
        let del2 = key(7);
        let c = StepInfo::parse(&mk(Some(g.id), &del, del2.verifying_key().to_bytes())).unwrap();
        assert_eq!(c.bytes.len(), crate::msg::MAX_STEP_BYTES);
        assert!(g.is_parent_of(&c));
        assert!(!c.is_valid_genesis());
        let forged = StepInfo::parse(&mk(Some(g.id), &del2, del2.verifying_key().to_bytes())).unwrap();
        assert!(!g.is_parent_of(&forged));
        let other = key(9);
        let bad_genesis = StepInfo::parse(&mk(None, &other, other.verifying_key().to_bytes())).unwrap();
        assert!(!bad_genesis.is_valid_genesis());
    }

    // spec/wire.md §8: claim count a power of two, box keys among the claims
    #[test]
    fn claim_sets() {
        let cs = ClaimSet { claims: vec![[1; 32], [2; 32]], boxes: BTreeMap::from([([2; 32], cbor::encode(&Value::Bytes(vec![9; 49])))]) };
        assert_eq!(ClaimSet::parse(&cs.to_bytes().unwrap()), Ok(cs));
        let three = ClaimSet { claims: vec![[1; 32], [2; 32], [3; 32]], boxes: BTreeMap::new() };
        assert!(ClaimSet::parse(&three.to_bytes().unwrap()).is_err());
        let stray = ClaimSet { claims: vec![[1; 32]], boxes: BTreeMap::from([([2; 32], cbor::encode(&Value::Int(0)))]) };
        assert!(ClaimSet::parse(&stray.to_bytes().unwrap()).is_err());
    }

    // spec/wire.md §5: prefix layout; unknown framing version reads as no expiry, no commitments
    #[test]
    fn prefixes() {
        let mut p = vec![1u8];
        p.extend([7; 16]);
        p.extend(99u64.to_le_bytes());
        p.push(2);
        p.extend([1; 17]);
        p.extend([2; 17]);
        p.extend([0xcc; 10]);
        assert_eq!(prefix(&p), Ok(Prefix { salt: [7; 16], expiry: Some(99), commitments: vec![[1; 17], [2; 17]] }));
        assert_eq!(prefix(&[2, 0]), Ok(Prefix::default()));
        assert!(prefix(&p[..40]).is_err());
        let mut unsorted = p.clone();
        unsorted[26] = 3;
        assert!(prefix(&unsorted).is_err());
        assert!(prefix(&[]).is_err());
    }
}
