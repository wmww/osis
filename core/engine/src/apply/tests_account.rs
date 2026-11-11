mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::apply::Reason;
    use crate::local_peer::LocalPeer;
    use crate::Ingested;
    use osis_base::{Ak, CommitId, CreationRecord, Tid, Ts, WallMs};
    use osis_commit::{AccountSigner, AspectWrite, CommitBuilder, FIRST_EPOCH, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    use osis_crypto::{AccountEpochKeys, KeyActorKeys, Secret32};

    struct Dedup(Vec<CreationRecord>);
    impl osis_commit::Secrets for Dedup {
        fn dedup(&self, t: &Tid) -> Option<Secret32> {
            self.0.iter().find(|r| r.tid() == *t).map(|r| osis_crypto::dedup_secret(r.nonce()))
        }
        fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
            None
        }
        fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
            None
        }
        fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
            None
        }
    }

    /// An account's first commit: its own record and a thing it is first admin of, signed with
    /// `key` at `epoch`, with an inner signature by a node when `inner`.
    fn account_commit(seed: u8, key: &AccountEpochKeys, epoch: CommitId, inner: bool, ts: Ts) -> (Tid, Vec<u8>) {
        let first = AccountEpochKeys::from_seed(&Secret32::from_bytes([seed; 32]));
        let p = CreationRecord::KeyActor { alg: 1, public_key: first.signing.verifying_key().to_bytes().to_vec(), nonce: [seed; 32], account: true };
        let pt = p.tid();
        let t = CreationRecord::Thing { admin: pt, nonce: [seed ^ 1; 32], link: None };
        let ak = Ak::new("created.0").unwrap();
        let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
        let mut cb = CommitBuilder::new(Kind::Role, ts, pt, pt, Form::Commit);
        let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1);
        for rec in [&p, &t] {
            let f = create(&mut w, &view, &rec.to_value()).unwrap();
            let r = w.range();
            let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Form::Commit, Kind::Role, ts, pt, r.lo, r.hi), None).unwrap();
            let mut aw = AspectWrite::new(rec.tid(), ak.clone(), r.lo, r.hi, bytes);
            aw.retention = osis_commit::retention::KEPT_RETENTION;
            cb.aspects.push(aw);
            w = Writer::new(ts, Source::commit(CommitId([0; 32])), r.hi);
        }
        let node = KeyActorKeys::from_seed(&Secret32::from_bytes([seed ^ 2; 32]));
        // without: an account author signing as a key actor would
        cb.account = inner.then(|| AccountSigner { epoch, inner: key.inner.clone(), node: Tid::from_bytes([seed; 15]), node_key: node.signing.clone() });
        let built = cb.build(&key.signing, &Dedup(vec![p, t]), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap();
        (pt, built.commit.encode())
    }

    // spec/wire.md §4 fields 15, 16 and the inner signature; spec/permissions.md §4: an account's
    // commit is signed by the epoch its header names, the first by the key its creation record
    // commits to; one at an epoch whose rotation is not held is pending; a commit by an account
    // without its epoch and inner signature, or signed by another epoch's key, is refused.
    #[test]
    fn account_commit_signed_at_its_epoch_spec_wire_4() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let ts = Ts::make(lp.peers[0].engine.now(), 0).unwrap();
        let first = AccountEpochKeys::from_seed(&Secret32::from_bytes([40; 32]));
        let (p, bytes) = account_commit(40, &first, FIRST_EPOCH, true, ts);
        assert!(matches!(lp.peers[0].engine.ingest(&bytes, Vec::new()).unwrap(), Ingested::Applied(_)));
        assert!(lp.peers[0].engine.core.created(&p).is_some_and(CreationRecord::is_account));
        // an epoch no held rotation mints: pending
        let later = CommitId([5; 32]);
        let k2 = AccountEpochKeys::from_seed(&Secret32::from_bytes([41; 32]));
        let (_, bytes) = account_commit(41, &k2, later, true, ts);
        assert!(matches!(lp.peers[0].engine.ingest(&bytes, Vec::new()).unwrap(), Ingested::Pending(_, Reason::Epoch(e)) if e == later));
        // the first epoch signed by another key
        let (_, bytes) = account_commit(42, &k2, FIRST_EPOCH, true, ts);
        assert!(lp.peers[0].engine.ingest(&bytes, Vec::new()).is_err());
        // no epoch, no inner signature
        let k3 = AccountEpochKeys::from_seed(&Secret32::from_bytes([43; 32]));
        let (_, bytes) = account_commit(43, &k3, FIRST_EPOCH, false, ts);
        assert!(lp.peers[0].engine.ingest(&bytes, Vec::new()).is_err());
    }
}
