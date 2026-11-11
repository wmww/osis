//! Connection proofs (spec/sync.md §10 Connection proofs, spec/wire.md §11.2 Prove): each proof
//! shows the prover holds an actor's signing key on this connection. The signature covers the
//! prover's role, the verifier's Hello challenge and the listener's static key (the one key both
//! sides authenticated for the connection, whichever of them proves). Invariant: a proof made as
//! one role cannot be accepted in the other, and is bound to one challenge and one listener.
//! An account signs with one of its epochs' keys; whether that epoch is open is the node's to
//! judge (`osis_node`).

use crate::Error;
use crate::dec::Fields;
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey, proof_digest};

/// Most proofs in one Prove or Proved; past it the message is refused whole. Resource bound: a
/// stranger pays one signature per proof, so this bounds its verification cost per connection
/// (about 12 ms at 46 us each). 0: no connection proves anything; infinity: a frame of proofs costs
/// seconds of the event loop. A node holding more key actors proves its own key and the first of
/// them by tid (`osis_node`'s `provers`); the rest are not proved on that connection.
pub const MAX_PROOFS: usize = 256;

/// Most tags one Resume holds: as many as fit one message (spec/wire.md §11.2). Not picked: the
/// message bound divided by a tag's encoding. A dialer holding more lists its most recent.
pub const MAX_RESUME_TAGS: usize = (osis_base::format::MAX_MESSAGE - 64) / 33;

/// A proof as the prover holds it, before the verifier's challenge is known.
#[derive(Clone)]
pub struct Prover {
    /// The actor's signing key: for an account, its signing key at the epoch it proves at.
    pub key: SigningSecret,
    /// The actor's creation record: its tid commits to the first key.
    pub record: CreationRecord,
}

impl Prover {
    pub fn sign(&self, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> ActorProof {
        ActorProof { record: self.record.clone(), key: self.key.verifying_key().to_bytes(), sig: self.key.sign(Domain::ConnectionProof, &proof_digest(by_listener, challenge, listener_key)) }
    }
}

/// `actor_proof := [record, key, sig]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorProof {
    pub record: CreationRecord,
    /// The key that signed: the record's own, or for an account its signing key at some epoch.
    pub key: [u8; 32],
    pub sig: Signature,
}

impl ActorProof {
    /// The actor proved: the record's tid.
    pub fn actor(&self) -> Tid {
        self.record.tid()
    }

    /// Whether `key` signed this connection's challenge and may stand for the record: a key
    /// actor's own key, or for an account any key (which epoch it is the node's to judge). Any
    /// other record (a thing, a key of another algorithm) proves nothing.
    pub fn verify(&self, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> bool {
        let CreationRecord::KeyActor { public_key, account, .. } = &self.record else { return false };
        (*account || public_key.as_slice() == self.key.as_slice()) && VerifyingKey::from_slice(&self.key).is_ok_and(|k| k.verify(Domain::ConnectionProof, &proof_digest(by_listener, challenge, listener_key), &self.sig).is_ok())
    }

    pub fn to_value(&self) -> Value {
        Value::List(vec![self.record.to_value(), Value::bytes(&self.key), Value::bytes(&self.sig.0)])
    }

    pub fn from_value(v: Value) -> Result<ActorProof, Error> {
        let mut f = Fields::exact(v, 3, "actor proof")?;
        let record = CreationRecord::from_value(&f.next()?).ok_or(Error::Malformed("actor proof record"))?;
        let key = f.fixed()?;
        let sig = Signature(f.fixed()?);
        f.end()?;
        Ok(ActorProof { record, key, sig })
    }
}

/// The proofs that verify, in order, as made by `by_listener` over `challenge` and `listener_key`.
/// Stops at the first that does not: a bad proof comes only from a hostile peer, and a message of
/// bad signatures costs the peer's event loop one check, not one per proof.
pub fn verified(proofs: Vec<ActorProof>, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> Vec<ActorProof> {
    proofs.into_iter().take_while(|p| p.verify(by_listener, challenge, listener_key)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::Secret32;

    fn prover(seed: u8) -> Prover {
        let key = SigningSecret::from_seed(&Secret32::from_bytes([seed; 32]));
        let record = CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [seed; 32], account: false };
        Prover { key, record }
    }

    // spec/wire.md §11.2 Prove: a proof verifies only with the challenge and listener key it
    // was signed over, under the record's own key
    #[test]
    fn proof_binds_challenge_listener_and_key_spec_wire_11_2() {
        let (c, l) = ([1; 32], [2; 32]);
        let p = prover(9).sign(false, &c, &l);
        assert!(p.verify(false, &c, &l), "the proof it was made for");
        assert!(!p.verify(true, &c, &l), "the other direction");
        assert!(!p.verify(false, &[3; 32], &l), "another session's challenge");
        assert!(!p.verify(false, &c, &[3; 32]), "another listener");
        let mut forged = p.clone();
        forged.record = prover(8).record;
        assert!(!forged.verify(false, &c, &l), "another actor's record");
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

    // spec/wire.md §11.2 Prove: a record that names no key actor proves nothing
    #[test]
    fn record_of_a_thing_proves_nothing_spec_wire_11_2() {
        let mut p = prover(9).sign(false, &[1; 32], &[2; 32]);
        p.record = CreationRecord::Thing { admin: Tid::from_bytes([1; 15]), nonce: [0; 32], link: None };
        assert!(!p.verify(false, &[1; 32], &[2; 32]));
    }

    // spec/wire.md §11.2 Prove: `MAX_PROOFS` proofs fit a frame
    #[test]
    fn caps_fit_a_frame_spec_wire_11_2() {
        let proofs = vec![prover(8).sign(false, &[1; 32], &[2; 32]); MAX_PROOFS];
        assert!(crate::encode_frame(&crate::Message::Prove { id: 1, proofs }.encode()).len() <= osis_base::format::MAX_MESSAGE);
    }

    // spec/wire.md §11.2 Prove: encodes and decodes
    #[test]
    fn proof_round_trips_spec_wire_11_2() {
        let p = prover(9).sign(false, &[1; 32], &[2; 32]);
        assert_eq!(ActorProof::from_value(p.to_value()), Ok(p));
    }
}
