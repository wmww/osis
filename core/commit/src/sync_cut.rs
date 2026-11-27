//! Sync-only cuts (spec/wire.md §4 `SyncOnlyCut := [tid, sync_id]`, spec/permissions.md §4 Stub):
//! a stub's sync-only cut, the thing and its sync ID. No header; it is read for the sync ID alone
//! and nothing of it applies.

use crate::cbor::item;
use crate::header::LIMITS;
use crate::Error;
use osis_base::cbor::{Item, put_array, put_bytes};
use osis_base::{SyncId, Tid};

/// A sync-only cut's plaintext: a thing and its sync ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyncOnlyCut {
    pub thing: Tid,
    pub sync_id: SyncId,
}

impl SyncOnlyCut {
    /// Canonical bytes (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_array(&mut out, 2);
        put_bytes(&mut out, self.thing.as_bytes());
        put_bytes(&mut out, &self.sync_id.0);
        out
    }

    /// Reads a sync-only cut's plaintext: canonical.
    pub fn decode(b: &[u8]) -> Result<SyncOnlyCut, Error> {
        let Some([t, s]) = item::list(Item::parse(b, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("sync-only cut arity")) };
        let cut = SyncOnlyCut { thing: item::tid(t)?, sync_id: SyncId(item::bytes(s)?) };
        if cut.encode() != b {
            return Err(Error::Malformed("sync-only cut not canonical"));
        }
        Ok(cut)
    }

    /// Whether `plain`, a blob's plaintext, is a sync-only cut's by its shape (a 2-array whose
    /// first element is a 15-byte string; a commit blob's begins with its header, an array),
    /// without reading it: what picks the decoder.
    pub fn is_shaped(plain: &[u8]) -> bool {
        matches!(plain, [0x82, 0x4f, ..])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/wire.md §4 (sync-only cut): round-trips; bytes not canonical are bad input; its shape
    // tells it from a commit blob's plaintext
    #[test]
    fn a_sync_only_cut_round_trips_spec_wire_4() {
        let c = SyncOnlyCut { thing: Tid::from_bytes([3; 15]), sync_id: SyncId([7; 16]) };
        let b = c.encode();
        assert!(SyncOnlyCut::is_shaped(&b));
        assert_eq!(SyncOnlyCut::decode(&b).unwrap(), c);
        let mut bad = b.clone();
        bad.push(0);
        assert!(SyncOnlyCut::decode(&bad).is_err(), "trailing bytes");
        assert!(SyncOnlyCut::decode(&b[..b.len() - 1]).is_err(), "short sync ID");
    }
}
