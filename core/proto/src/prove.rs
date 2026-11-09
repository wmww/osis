//! Connection proofs (spec/sync.md §10 Connection proofs, spec/wire.md §11.2 Prove): each proof
//! shows the prover holds an actor's signing key on this connection. The signature covers the
//! verifier's Hello challenge and the listener's static key (the one key both sides authenticated
//! for the connection, whichever of them proves), so a proof made for one connection proves nothing on another.
//! What a proof's chain shows about an account is the node's to judge (`osis_node`).

use crate::Error;
use crate::dec::{self, Fields};
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey, proof_digest};

/// A proof as the prover holds it, before the verifier's challenge is known.
#[derive(Clone)]
pub struct Prover {
    pub key: SigningSecret,
    /// The actor's creation record: its tid commits to the key.
    pub record: CreationRecord,
    /// Accounts this actor claims, shown by `chain`.
    pub accounts: Vec<Tid>,
    /// Chain certificates (canonical partial commit blobs), the prover's own, never group data.
    pub chain: Vec<Vec<u8>>,
}

impl Prover {
    pub fn sign(&self, challenge: &[u8; 32], listener_key: &[u8; 32]) -> ActorProof {
        ActorProof { record: self.record.clone(), sig: self.key.sign(Domain::ConnectionProof, &proof_digest(challenge, listener_key)), accounts: self.accounts.clone(), chain: self.chain.clone() }
    }
}

/// `actor_proof := [record, sig, [account*], [commit_blob*]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorProof {
    pub record: CreationRecord,
    pub sig: Signature,
    pub accounts: Vec<Tid>,
    pub chain: Vec<Vec<u8>>,
}

impl ActorProof {
    /// The actor proved: the record's tid.
    pub fn actor(&self) -> Tid {
        self.record.tid()
    }

    /// Whether the actor's key signed this connection's challenge. Any other record (a thing, a
    /// key of another algorithm) proves nothing.
    pub fn verify(&self, challenge: &[u8; 32], listener_key: &[u8; 32]) -> bool {
        let CreationRecord::KeyActor { public_key, .. } = &self.record else { return false };
        VerifyingKey::from_slice(public_key).is_ok_and(|k| k.verify(Domain::ConnectionProof, &proof_digest(challenge, listener_key), &self.sig).is_ok())
    }

    pub fn to_value(&self) -> Value {
        Value::List(vec![
            self.record.to_value(),
            Value::bytes(&self.sig.0),
            Value::List(self.accounts.iter().map(|t| Value::bytes(t.as_bytes())).collect()),
            Value::List(self.chain.iter().map(|b| Value::Bytes(b.clone())).collect()),
        ])
    }

    pub fn from_value(v: Value) -> Result<ActorProof, Error> {
        let mut f = Fields::exact(v, 4, "actor proof")?;
        let record = CreationRecord::from_value(&f.next()?).ok_or(Error::Malformed("actor proof record"))?;
        let sig = Signature(f.fixed()?);
        let accounts = f.list(0, usize::MAX, "actor proof accounts")?.into_iter().map(|v| dec::fixed(v, "account").map(Tid::from_bytes)).collect::<Result<_, _>>()?;
        let chain = f.list(0, usize::MAX, "actor proof chain")?.into_iter().map(|v| dec::bytes(v, usize::MAX, "chain blob")).collect::<Result<_, _>>()?;
        f.end()?;
        Ok(ActorProof { record, sig, accounts, chain })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::Secret32;

    fn prover(seed: u8) -> Prover {
        let key = SigningSecret::from_seed(&Secret32::from_bytes([seed; 32]));
        let record = CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [seed; 32] };
        Prover { key, record, accounts: Vec::new(), chain: Vec::new() }
    }

    // spec/wire.md §11.2 Prove: a proof verifies only with the challenge and listener key it
    // was signed over, under the record's own key
    #[test]
    fn proof_binds_challenge_listener_and_key_spec_wire_11_2() {
        let (c, l) = ([1; 32], [2; 32]);
        let p = prover(9).sign(&c, &l);
        assert!(p.verify(&c, &l), "the proof it was made for");
        assert!(!p.verify(&[3; 32], &l), "another session's challenge");
        assert!(!p.verify(&c, &[3; 32]), "another listener");
        let mut forged = p.clone();
        forged.record = prover(8).record;
        assert!(!forged.verify(&c, &l), "another actor's record");
    }

    // spec/wire.md §11.2 Prove: a record that names no key actor proves nothing
    #[test]
    fn record_of_a_thing_proves_nothing_spec_wire_11_2() {
        let mut p = prover(9).sign(&[1; 32], &[2; 32]);
        p.record = CreationRecord::Thing { admin: Tid::from_bytes([1; 15]), nonce: [0; 32], link: false };
        assert!(!p.verify(&[1; 32], &[2; 32]));
    }

    // spec/wire.md §11.2 Prove: encodes and decodes
    #[test]
    fn proof_round_trips_spec_wire_11_2() {
        let mut pr = prover(9);
        pr.accounts.push(Tid::from_bytes([3; 15]));
        pr.chain.push(vec![1, 2, 3]);
        let p = pr.sign(&[1; 32], &[2; 32]);
        assert_eq!(ActorProof::from_value(p.to_value()), Ok(p));
    }
}
