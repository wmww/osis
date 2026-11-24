//! Connection proofs (spec/sync-opens.md §2, spec/wire.md §11.2 Prove): each proof is a signature
//! by a signing key over this connection, standing for a thing (its creation record) and the path
//! it claims through other things. The signature covers the prover's side, the verifier's Hello
//! challenge and the listener's static key (the one key both sides authenticated for the
//! connection, whichever of them proves). Invariant: a proof made as one side cannot be accepted
//! in the other, and is bound to one challenge and one listener. Whether the key holds a grant on
//! the thing, and what the path gives, is the verifier's judgement (osis-engine), not this layer's.

use crate::Error;
use crate::dec::Fields;
use osis_base::format::MAX_PATH_THINGS;
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey, proof_digest};

/// A proof as the prover holds it, before the verifier's challenge is known.
#[derive(Clone)]
pub struct Prover {
    /// A signing key holding a grant on the thing.
    pub key: SigningSecret,
    /// The thing's creation record.
    pub record: CreationRecord,
    /// The things it claims to act through, in order.
    pub path: Vec<Tid>,
}

impl Prover {
    pub fn sign(&self, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> Proof {
        Proof { record: self.record.clone(), key: self.key.verifying_key().to_bytes(), sig: self.key.sign(Domain::ConnectionProof, &proof_digest(by_listener, challenge, listener_key)), path: self.path.clone() }
    }
}

/// A proof `[creation, key, sig, [tid*]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub record: CreationRecord,
    /// The key that signed.
    pub key: [u8; 32],
    pub sig: Signature,
    /// The things it claims to act through: at most `MAX_PATH_THINGS`, none twice, none the
    /// proven thing.
    pub path: Vec<Tid>,
}

impl Proof {
    /// The thing proved: the record's tid.
    pub fn thing(&self) -> Tid {
        self.record.tid()
    }

    /// Whether `key` signed this connection's challenge, as made by `by_listener`.
    pub fn verify(&self, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> bool {
        VerifyingKey::from_slice(&self.key).is_ok_and(|k| k.verify(Domain::ConnectionProof, &proof_digest(by_listener, challenge, listener_key), &self.sig).is_ok())
    }

    pub fn to_value(&self) -> Value {
        Value::List(vec![self.record.to_value(), Value::bytes(&self.key), Value::bytes(&self.sig.0), Value::List(self.path.iter().map(|t| Value::bytes(t.as_bytes())).collect())])
    }

    pub fn from_value(v: Value) -> Result<Proof, Error> {
        let mut f = Fields::exact(v, 4, "proof")?;
        let record = CreationRecord::from_value(&f.next()?).ok_or(Error::Malformed("proof record"))?;
        let key = f.fixed()?;
        let sig = Signature(f.fixed()?);
        let path: Vec<Tid> = f.list(0, MAX_PATH_THINGS, "proof path")?.into_iter().map(|t| crate::dec::fixed(t, "path tid").map(Tid::from_bytes)).collect::<Result<_, _>>()?;
        f.end()?;
        let me = record.tid();
        let mut seen = std::collections::BTreeSet::new();
        if path.iter().any(|t| *t == me || !seen.insert(*t)) {
            return Err(Error::Malformed("proof path"));
        }
        Ok(Proof { record, key, sig, path })
    }
}

/// The proofs that verify, in order, as made by `by_listener` over `challenge` and `listener_key`.
/// Stops at the first that does not: a bad proof comes only from a hostile peer, and a message of
/// bad signatures costs the peer's event loop one check, not one per proof.
pub fn verified(proofs: Vec<Proof>, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> Vec<Proof> {
    proofs.into_iter().take_while(|p| p.verify(by_listener, challenge, listener_key)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::Secret32;

    fn prover(seed: u8) -> Prover {
        let key = SigningSecret::from_seed(&Secret32::from_bytes([seed; 32]));
        let record = CreationRecord::with_key(osis_base::SignKey(key.verifying_key().to_bytes()), [seed; 32]);
        Prover { key, record, path: vec![Tid::from_bytes([seed; 15])] }
    }

    // spec/wire.md §11.2 Prove: a proof verifies only with the challenge and listener key it
    // was signed over, under the key it names
    #[test]
    fn proof_binds_challenge_listener_and_key_spec_wire_11_2() {
        let (c, l) = ([1; 32], [2; 32]);
        let p = prover(9).sign(false, &c, &l);
        assert!(p.verify(false, &c, &l), "the proof it was made for");
        assert!(!p.verify(true, &c, &l), "the other direction");
        assert!(!p.verify(false, &[3; 32], &l), "another session's challenge");
        assert!(!p.verify(false, &c, &[3; 32]), "another listener");
        let mut forged = p.clone();
        forged.key = prover(8).key.verifying_key().to_bytes();
        assert!(!forged.verify(false, &c, &l), "another key");
    }

    // spec/wire.md §11.2 Prove: checking stops at the first proof that does not verify: the ones
    // before it stand, it and the ones after it prove nothing
    #[test]
    fn checking_stops_at_the_first_bad_proof_spec_wire_11_2() {
        let (c, l) = ([1; 32], [2; 32]);
        let good = prover(9).sign(false, &c, &l);
        let also = prover(8).sign(false, &c, &l);
        let bad = prover(7).sign(false, &[3; 32], &l);
        assert_eq!(verified(vec![good.clone(), bad.clone(), also.clone()], false, &c, &l), vec![good.clone()], "those before the bad one");
        assert_eq!(verified(vec![bad, good, also], false, &c, &l), Vec::new(), "a bad first proof ends it");
    }

    // spec/wire.md §11.2 Prove: a path naming the proven thing or a thing twice is malformed
    #[test]
    fn a_path_is_a_paths_list_spec_wire_11_2() {
        let mut p = prover(9).sign(false, &[1; 32], &[2; 32]);
        p.path = vec![p.thing()];
        assert!(Proof::from_value(p.to_value()).is_err(), "the proven thing");
        p.path = vec![Tid::from_bytes([1; 15]); 2];
        assert!(Proof::from_value(p.to_value()).is_err(), "a thing twice");
        p.path = (0..=MAX_PATH_THINGS as u8).map(|i| Tid::from_bytes([i; 15])).collect();
        assert!(Proof::from_value(p.to_value()).is_err(), "past MAX_PATH_THINGS");
    }

    // spec/wire.md §11.2 Prove: `MAX_PROOFS` proofs fit a frame
    #[test]
    fn caps_fit_a_frame_spec_wire_11_2() {
        let proofs = vec![prover(8).sign(false, &[1; 32], &[2; 32]); crate::limits::MAX_PROOFS];
        assert!(crate::encode_frame(&crate::Msg::Prove { id: 1, proofs, copies: Default::default() }.encode()).len() <= osis_base::format::MAX_MESSAGE);
    }

    // spec/wire.md §11.2 Prove: encodes and decodes
    #[test]
    fn proof_round_trips_spec_wire_11_2() {
        let p = prover(9).sign(false, &[1; 32], &[2; 32]);
        assert_eq!(Proof::from_value(p.to_value()), Ok(p));
    }
}
