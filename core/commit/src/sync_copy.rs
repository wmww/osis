//! Sync copies (spec/wire.md §4 `SyncCopyPlaintext`): a holder of only sync's copy of a role
//! commit on a thing, `[commit_id, tid, Opt(Delta), Opt(Delta)]`:
//! its `secrets.0` piece and the commit's `sync.0` delta on the thing. No header: its reader
//! learns no signer, path or other holder (spec/sync-ids.md §2 What a sync holder learns). It is
//! read for its boxes and steps alone; nothing of it applies and no hash checks its deltas, so a
//! box in it proves itself only by a step bearing its secret's sync key (the reader's rule).

use crate::cbor::item;
use crate::header::LIMITS;
use crate::Error;
use osis_base::cbor::{Item, head, put_array, put_bytes, MAJOR_ARRAY};
use osis_base::{CommitId, Tid};

/// A sync copy's plaintext: the commit, the thing, the holder's `secrets.0` piece (none where
/// the commit boxes it nothing) and the commit's `sync.0` delta on the thing (none where it has
/// none); at least one of the two. Each delta is its canonical `Delta` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCopy {
    pub commit: CommitId,
    pub thing: Tid,
    pub piece: Option<Vec<u8>>,
    pub sync: Option<Vec<u8>>,
}

impl SyncCopy {
    /// Canonical bytes (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_array(&mut out, 4);
        put_bytes(&mut out, &self.commit.0);
        put_bytes(&mut out, self.thing.as_bytes());
        for d in [&self.piece, &self.sync] {
            match d {
                Some(d) => {
                    head(&mut out, MAJOR_ARRAY, 1);
                    out.extend_from_slice(d);
                }
                None => put_array(&mut out, 0),
            }
        }
        out
    }

    /// Reads a sync copy's plaintext: canonical, each delta an array, at least one present.
    /// The holder rule (a piece keyed with one holder, the one whose copy it is) is its
    /// reader's, which decodes the piece.
    pub fn decode(b: &[u8]) -> Result<SyncCopy, Error> {
        let Some([c, t, p, s]) = item::list(Item::parse(b, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("sync copy arity")) };
        let delta = |v: Item| -> Result<Option<Vec<u8>>, Error> {
            match item::opt(v)? {
                Some(d) if d.as_list().is_some() => Ok(Some(d.bytes().to_vec())),
                Some(_) => Err(Error::Malformed("sync copy delta")),
                None => Ok(None),
            }
        };
        let copy = SyncCopy { commit: CommitId(item::bytes(c)?), thing: item::tid(t)?, piece: delta(p)?, sync: delta(s)? };
        if copy.piece.is_none() && copy.sync.is_none() {
            return Err(Error::Malformed("a sync copy of no delta"));
        }
        if copy.encode() != b {
            return Err(Error::Malformed("sync copy not canonical"));
        }
        Ok(copy)
    }

    /// Whether `plain`, a blob's plaintext, is a sync copy's by its shape (a 4-array whose first
    /// element is a byte string; a commit blob's begins with its header, an array), without
    /// reading it: what picks the decoder.
    pub fn is_shaped(plain: &[u8]) -> bool {
        matches!(plain, [0x84, 0x58, 32, ..])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn delta(n: u8) -> Vec<u8> {
        osis_base::encode(&osis_base::Value::List(vec![osis_base::Value::Int(i64::from(n))]))
    }

    // spec/wire.md §4 (sync copy): round-trips with either delta absent; one of no delta, a
    // delta that is no array, or bytes not canonical is bad input; its shape tells it from a
    // commit blob's plaintext
    #[test]
    fn a_sync_copy_round_trips_spec_wire_4() {
        let c = SyncCopy { commit: CommitId([7; 32]), thing: Tid::from_bytes([3; 15]), piece: Some(delta(1)), sync: None };
        for x in [c.clone(), SyncCopy { piece: None, sync: Some(delta(2)), ..c.clone() }, SyncCopy { sync: Some(delta(2)), ..c.clone() }] {
            let b = x.encode();
            assert!(SyncCopy::is_shaped(&b));
            assert_eq!(SyncCopy::decode(&b).unwrap(), x);
        }
        assert!(SyncCopy::decode(&SyncCopy { piece: None, ..c.clone() }.encode()).is_err(), "no delta");
        let mut bad = c.encode();
        bad.push(0);
        assert!(SyncCopy::decode(&bad).is_err(), "trailing bytes");
        let not_array = osis_base::encode(&osis_base::Value::List(vec![osis_base::Value::Bytes(vec![7; 32]), osis_base::Value::Bytes(vec![3; 15]), osis_base::Value::List(vec![osis_base::Value::Int(1)]), osis_base::Value::List(vec![])]));
        assert!(SyncCopy::decode(&not_array).is_err(), "a delta that is no array");
    }
}
