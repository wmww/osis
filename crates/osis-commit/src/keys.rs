//! Delete keys of a commit by level and blob prefix inputs (spec/crypto.md §7, spec/wire.md §5).

use crate::header::{DeleteKey, Kind};
use crate::retention::delete_levels;
use crate::Error;
use osis_core::Tid;
use osis_crypto::{Secret32, VerifyingKey, commitment};
use osis_schema::Retention;

/// What a writer supplies (osis-keys and the node implement it).
pub trait Secrets {
    /// Dedup secret of a thing (spec/crypto.md §3).
    fn dedup(&self, tid: &Tid) -> Option<Secret32>;
    /// The thing's admin delete key (level 1): derived from its newest admin secret, or the
    /// published one when that secret is not held.
    fn admin_key(&self, tid: &Tid) -> Option<VerifyingKey>;
    /// The write delete key of the actor directly above the author node in its chain (level 2).
    fn chain_key(&self) -> Option<VerifyingKey>;
    /// The thing's write delete key (level 3).
    fn write_key(&self, tid: &Tid) -> Option<VerifyingKey>;
}

/// Delete keys of a delta on `tid` with retention `r` in a commit of `kind`: one per level its
/// retention calls for; a missing one is an error.
pub fn delete_keys(s: &dyn Secrets, tid: &Tid, r: &Retention, kind: Kind) -> Result<Vec<DeleteKey>, Error> {
    delete_levels(r, kind)
        .iter()
        .map(|level| {
            let key = match level {
                1 => s.admin_key(tid).ok_or(Error::Build("admin delete key not supplied"))?,
                2 => s.chain_key().ok_or(Error::Build("author-chain delete key not supplied"))?,
                _ => s.write_key(tid).ok_or(Error::Build("write delete key not supplied"))?,
            };
            Ok(DeleteKey::new(*level, &key))
        })
        .collect()
}

/// Clear blob prefix inputs (spec/wire.md §5); osis-label lays them out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub salt: [u8; 16],
    /// Expiry `T`, wall ms.
    pub expiry: Option<u64>,
    /// Commitments, levels strictly ascending.
    pub commitments: Vec<[u8; 33]>,
}

impl Prefix {
    /// Prefix of a blob serving deltas whose delete keys are `keys`, each blinded by `salt`.
    pub fn from_keys(salt: [u8; 16], expiry: Option<u64>, keys: &[DeleteKey]) -> Result<Prefix, Error> {
        let mut commitments = keys.iter().map(|k| Ok(commitment(k.level, &k.verifying_key()?, &salt)?)).collect::<Result<Vec<_>, Error>>()?;
        commitments.sort_unstable();
        commitments.dedup();
        if commitments.windows(2).any(|w| matches!(w, [a, b] if a[0] == b[0])) {
            return Err(Error::Invalid("two delete keys at one level in one blob"));
        }
        Ok(Prefix { salt, expiry, commitments })
    }
}
