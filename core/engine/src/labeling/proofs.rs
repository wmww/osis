//! What a connection's proof exchange shows about accounts (spec/sync.md §10, Connection proofs).

use crate::engine::Engine;
use crate::error::Result;
use osis_base::CreationRecord;
use osis_crypto::SigningSecret;

impl Engine {
    /// This node's account at the newest open epoch it holds a seed of: the signing key and the
    /// account's creation record. `None` before it holds one or once no open epoch is held.
    pub fn account_prover(&self) -> Result<Option<(SigningSecret, CreationRecord)>> {
        let Some(p) = self.core.account else { return Ok(None) };
        let Some(record) = self.core.created(&p).cloned() else { return Ok(None) };
        Ok(self.core.account_signing(&p)?.map(|(_, keys)| (keys.signing, record)))
    }

    /// Whether `key` signs for the account `record` creates at an epoch open by the rotations
    /// held here: a closed epoch proves nothing (spec/sync.md §10). An account not held at all
    /// has only its first epoch to show: the record's key.
    pub fn account_key_open(&self, record: &CreationRecord, key: &[u8; 32]) -> bool {
        let CreationRecord::KeyActor { public_key, account: true, .. } = record else { return false };
        match self.core.account_view(&record.tid()) {
            Some(v) => v.open_key(key),
            None => public_key.as_slice() == key.as_slice(),
        }
    }
}
