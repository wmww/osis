//! The link keys a claim set lists by static entry (spec/sync-ids.md §3).

use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CreationRecord, Tid};
use osis_crypto::VerifyingKey;

impl Engine {
    /// The signing keys of the link keys of `g`'s independent on its roster here, which a claim
    /// set lists by static entry (spec/sync-ids.md §3). O(roster).
    pub fn static_listed(&mut self, g: &Tid) -> Result<Vec<VerifyingKey>> {
        let a = self.core.reader_of(g);
        let keys = self.core.key_holders(&a).into_iter().filter_map(|(m, _)| self.core.created(&m).filter(|r| r.link_key_of() == Some(a)).and_then(CreationRecord::key));
        Ok(keys.filter_map(|k| VerifyingKey::from_bytes(&k.0).ok()).collect())
    }
}
