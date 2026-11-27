//! Sync-only cuts (spec/wire.md §4 `SyncOnlyCut := [tid, sync_id, [* tid]]`, spec/permissions.md
//! §4 Stub): a stub's sync-only cut, the thing, its sync ID and the holders on its unit's chains to
//! the thing. No header; it is read for the sync ID and the holders alone and nothing of it applies.

use crate::cbor::item;
use crate::header::LIMITS;
use crate::Error;
use osis_base::cbor::{Item, put_array, put_bytes};
use osis_base::{SyncId, Tid};

/// A sync-only cut's plaintext: a thing, its sync ID and the holders it names (ascending,
/// distinct, neither the thing nor the public).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyncOnlyCut {
    pub thing: Tid,
    pub sync_id: SyncId,
    pub holders: Vec<Tid>,
}

impl SyncOnlyCut {
    /// Canonical bytes (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_array(&mut out, 3);
        put_bytes(&mut out, self.thing.as_bytes());
        put_bytes(&mut out, &self.sync_id.0);
        put_array(&mut out, self.holders.len());
        for h in &self.holders {
            put_bytes(&mut out, h.as_bytes());
        }
        out
    }

    /// Reads a sync-only cut's plaintext: canonical.
    pub fn decode(b: &[u8]) -> Result<SyncOnlyCut, Error> {
        let Some([t, s, hs]) = item::list(Item::parse(b, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("sync-only cut arity")) };
        let holders = item::list(hs)?.map(item::tid).collect::<Result<Vec<_>, _>>()?;
        let cut = SyncOnlyCut { thing: item::tid(t)?, sync_id: SyncId(item::bytes(s)?), holders };
        if !crate::cbor::strictly_ascending(&cut.holders, |h| *h) || cut.holders.iter().any(|h| *h == cut.thing || h.is_public()) {
            return Err(Error::Malformed("sync-only cut holders"));
        }
        if cut.encode() != b {
            return Err(Error::Malformed("sync-only cut not canonical"));
        }
        Ok(cut)
    }

    /// Whether `plain`, a blob's plaintext, is a sync-only cut's by its shape (a 3-array whose
    /// first element is a 15-byte string; a commit blob's begins with its header, an array),
    /// without reading it: what picks the decoder.
    pub fn is_shaped(plain: &[u8]) -> bool {
        matches!(plain, [0x83, 0x4f, ..])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/wire.md §4 (sync-only cut): round-trips; bytes not canonical, or holders not ascending,
    // repeated or naming the thing, are bad input; its shape tells it from a commit blob's plaintext
    #[test]
    fn a_sync_only_cut_round_trips_spec_wire_4() {
        let (x, h1, h2) = (Tid::from_bytes([3; 15]), Tid::from_bytes([4; 15]), Tid::from_bytes([5; 15]));
        let c = SyncOnlyCut { thing: x, sync_id: SyncId([7; 16]), holders: vec![h1, h2] };
        let b = c.encode();
        assert!(SyncOnlyCut::is_shaped(&b));
        assert_eq!(SyncOnlyCut::decode(&b).unwrap(), c);
        let mut bad = b.clone();
        bad.push(0);
        assert!(SyncOnlyCut::decode(&bad).is_err(), "trailing bytes");
        assert!(SyncOnlyCut::decode(&b[..b.len() - 1]).is_err(), "short holder");
        for hs in [vec![h2, h1], vec![h1, h1], vec![x]] {
            let bad = SyncOnlyCut { holders: hs, ..c.clone() }.encode();
            assert!(SyncOnlyCut::decode(&bad).is_err(), "holders not ascending, repeated or the thing");
        }
    }
}
