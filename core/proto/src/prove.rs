//! Connection proofs (spec/sync.md §10 Connection proofs, spec/wire.md §11.2 Prove): each proof
//! shows the prover holds an actor's signing key on this connection. The signature covers the
//! prover's role, the verifier's Hello challenge and the listener's static key (the one key both
//! sides authenticated for the connection, whichever of them proves). Invariant: a proof made as
//! one role cannot be accepted in the other, and is bound to one challenge and one listener.
//! What a proof's chain shows about an account is the node's to judge (`osis_node`).

use crate::Error;
use crate::dec::{self, Fields};
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{Domain, Signature, SigningSecret, VerifyingKey, proof_digest};

/// Most proofs in one Prove or Proved; past it the message is refused whole. Resource bound: a
/// stranger pays one signature per proof, so this bounds its verification cost per connection
/// (about 12 ms at 46 us each). 0: no connection proves anything; infinity: a frame of proofs costs
/// seconds of the event loop. A node holding more key actors proves its own key and the first of
/// them by tid (`osis_node`'s `provers`); the rest are not proved on that connection.
pub const MAX_PROOFS: usize = 256;

/// Most account claims in one Prove or Proved; past it the message is refused whole. A node names
/// one account, and judging a claim walks the chain, so a claim per proof would make the check
/// quadratic. 0: no account is ever proved; infinity: claims times chain length.
pub const MAX_ACCOUNT_CLAIMS: usize = 1;

/// Most chain bytes in one Prove or Proved (1 MiB). A node whose chain is longer sends none and
/// proves its key alone; a message past it is refused whole. Resource bound: every commit of a
/// chain is signature-checked and walked before the verifier knows the requester, so this bounds a
/// stranger's cost per connection. A real chain is a handful of commits. 0: no account is ever
/// proved; infinity: a frame the peer rejects, and seconds of event loop per connection.
pub const MAX_CHAIN_BYTES: usize = 1 << 20;

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
    pub fn sign(&self, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> ActorProof {
        ActorProof { record: self.record.clone(), sig: self.key.sign(Domain::ConnectionProof, &proof_digest(by_listener, challenge, listener_key)), accounts: self.accounts.clone(), chain: self.chain.clone() }
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
    pub fn verify(&self, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> bool {
        let CreationRecord::KeyActor { public_key, .. } = &self.record else { return false };
        VerifyingKey::from_slice(public_key).is_ok_and(|k| k.verify(Domain::ConnectionProof, &proof_digest(by_listener, challenge, listener_key), &self.sig).is_ok())
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

/// The proofs that verify, in order, as made by `by_listener` over `challenge` and `listener_key`.
/// Stops at the first that does not: a bad proof comes only from a hostile peer, and a message of
/// bad signatures costs the peer's event loop one check, not one per proof.
pub fn verified(proofs: Vec<ActorProof>, by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> Vec<ActorProof> {
    proofs.into_iter().take_while(|p| p.verify(by_listener, challenge, listener_key)).collect()
}

/// The caps of one Prove or Proved (`MAX_PROOFS` is the decoder's list cap).
pub(crate) fn check_caps(proofs: &[ActorProof]) -> Result<(), Error> {
    if proofs.iter().map(|p| p.accounts.len()).sum::<usize>() > MAX_ACCOUNT_CLAIMS {
        return Err(Error::Cap("proof account claims"));
    }
    if proofs.iter().flat_map(|p| &p.chain).map(Vec::len).sum::<usize>() > MAX_CHAIN_BYTES {
        return Err(Error::Cap("proof chain bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::Secret32;

    fn prover(seed: u8) -> Prover {
        let key = SigningSecret::from_seed(&Secret32::from_bytes([seed; 32]));
        let record = CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [seed; 32], account: false };
        Prover { key, record, accounts: Vec::new(), chain: Vec::new() }
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
        p.record = CreationRecord::Thing { admin: Tid::from_bytes([1; 15]), nonce: [0; 32], link: false };
        assert!(!p.verify(false, &[1; 32], &[2; 32]));
    }

    // spec/wire.md §11.2 Prove: the caps' whole sum still fits a frame
    #[test]
    fn caps_fit_a_frame_spec_wire_11_2() {
        let mut p = prover(9);
        p.accounts = vec![Tid::from_bytes([3; 15]); MAX_ACCOUNT_CLAIMS];
        p.chain = vec![vec![0; MAX_CHAIN_BYTES]];
        let first = p.sign(false, &[1; 32], &[2; 32]);
        let mut proofs = vec![prover(8).sign(false, &[1; 32], &[2; 32]); MAX_PROOFS - 1];
        proofs.push(first);
        assert!(crate::encode_frame(&crate::Message::Prove { id: 1, proofs }.encode()).len() <= osis_base::format::MAX_MESSAGE);
    }

    // spec/wire.md §11.2 Prove: encodes and decodes
    #[test]
    fn proof_round_trips_spec_wire_11_2() {
        let mut pr = prover(9);
        pr.accounts.push(Tid::from_bytes([3; 15]));
        pr.chain.push(vec![1, 2, 3]);
        let p = pr.sign(false, &[1; 32], &[2; 32]);
        assert_eq!(ActorProof::from_value(p.to_value()), Ok(p));
    }
}
