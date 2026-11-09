//! A rotation's thing lists and list blobs (spec/wire.md §4, List tree; spec/permissions.md §5.5):
//! `ThingList := [tid, [commit_id*] | LINK, salt]`, `ThingCert := [rotation_id, index, [hash*],
//! ThingList]`, `ListBlobPlaintext := ["list", [ThingCert+]]`. Folding a cert to its rotation's
//! `list_root` is osis-perm's (`ListPath`).

use crate::cbor::{as_bytes, as_list, as_tid, as_uint, strictly_ascending, tid, uint};
use crate::header::LIMITS;
use crate::Error;
use osis_base::format::{CHUNK_THRESHOLD, LIST_TREE_DEPTH};
use osis_base::{CommitId, Link, Tid, Value};

/// A thing list's commit IDs: inline, or a link to a chunk tree of their canonical encoding
/// (above `CHUNK_THRESHOLD`, keyed by the thing's dedup secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListIds {
    Inline(Vec<CommitId>),
    Linked(Link),
}

/// One leaf of a rotation's list tree: rotation r names `ids` on `thing`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThingList {
    pub thing: Tid,
    pub ids: ListIds,
    pub salt: [u8; 16],
}

/// The canonical bytes of a list's commit IDs (`[commit_id*]`, ascending and distinct).
pub fn ids_bytes(ids: &[CommitId]) -> Vec<u8> {
    osis_base::encode(&Value::List(ids.iter().map(|c| Value::bytes(&c.0)).collect()))
}

/// Reads `[commit_id*]` bytes: ascending and distinct, else bad input.
pub fn read_ids(bytes: &[u8]) -> Result<Vec<CommitId>, Error> {
    let v = osis_base::decode(bytes, &LIMITS)?;
    let ids = as_list(&v)?.iter().map(|c| as_bytes(c).map(CommitId)).collect::<Result<Vec<_>, _>>()?;
    if !strictly_ascending(&ids, |c| *c) || osis_base::encode(&v) != bytes {
        return Err(Error::Malformed("thing list ids not sorted, distinct and canonical"));
    }
    Ok(ids)
}

impl ThingList {
    pub fn to_value(&self) -> Value {
        let ids = match &self.ids {
            ListIds::Inline(ids) => Value::List(ids.iter().map(|c| Value::bytes(&c.0)).collect()),
            ListIds::Linked(l) => Value::link(*l),
        };
        Value::List(vec![tid(&self.thing), ids, Value::bytes(&self.salt)])
    }

    /// The canonical bytes its leaf hashes (`osis_perm::epochs::list_leaf`).
    pub fn encode(&self) -> Vec<u8> {
        osis_base::encode(&self.to_value())
    }

    pub fn from_value(v: &Value) -> Result<ThingList, Error> {
        let [t, ids, salt] = as_list(v)? else { return Err(Error::Malformed("thing list arity")) };
        let ids = match ids {
            Value::Link(l) => ListIds::Linked(**l),
            v => {
                let bytes = osis_base::encode(v);
                if bytes.len() > CHUNK_THRESHOLD {
                    return Err(Error::Malformed("inline thing list above CHUNK_THRESHOLD"));
                }
                ListIds::Inline(read_ids(&bytes)?)
            }
        };
        Ok(ThingList { thing: as_tid(t)?, ids, salt: as_bytes(salt)? })
    }
}

/// A thing list with its place in the rotation's list tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThingCert {
    pub rotation: CommitId,
    pub index: u64,
    /// `LIST_TREE_DEPTH` sibling hashes, from the leaf up.
    pub siblings: Vec<[u8; 32]>,
    pub list: ThingList,
}

impl ThingCert {
    pub fn to_value(&self) -> Value {
        Value::List(vec![Value::bytes(&self.rotation.0), uint(self.index), Value::List(self.siblings.iter().map(|h| Value::bytes(h)).collect()), self.list.to_value()])
    }

    pub fn from_value(v: &Value) -> Result<ThingCert, Error> {
        let [r, i, sib, list] = as_list(v)? else { return Err(Error::Malformed("thing cert arity")) };
        let siblings = as_list(sib)?.iter().map(as_bytes).collect::<Result<Vec<[u8; 32]>, _>>()?;
        let index = as_uint(i)?;
        if siblings.len() != LIST_TREE_DEPTH as usize || index >> LIST_TREE_DEPTH != 0 {
            return Err(Error::Malformed("thing cert path"));
        }
        Ok(ThingCert { rotation: CommitId(as_bytes(r)?), index, siblings, list: ThingList::from_value(list)? })
    }
}

const LIST_TAG: &str = "list";

/// A list blob's plaintext (spec/wire.md §4): one or more thing certs.
pub fn encode_list_blob(certs: &[ThingCert]) -> Vec<u8> {
    osis_base::encode(&Value::List(vec![Value::Str(LIST_TAG.into()), Value::List(certs.iter().map(ThingCert::to_value).collect())]))
}

/// Whether a blob plaintext is a list blob's (by its first item), not a commit's.
pub fn is_list_blob(plain: &[u8]) -> bool {
    osis_base::decode(plain, &LIMITS).ok().and_then(|v| v.as_list().and_then(|l| l.first().cloned())) == Some(Value::Str(LIST_TAG.into()))
}

/// Reads a list blob's plaintext: canonical, at least one cert.
pub fn decode_list_blob(plain: &[u8]) -> Result<Vec<ThingCert>, Error> {
    let v = osis_base::decode(plain, &LIMITS)?;
    let [tag, certs] = as_list(&v)? else { return Err(Error::Malformed("list blob arity")) };
    if *tag != Value::Str(LIST_TAG.into()) {
        return Err(Error::Malformed("list blob tag"));
    }
    let certs = as_list(certs)?.iter().map(ThingCert::from_value).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() || osis_base::encode(&v) != plain {
        return Err(Error::Malformed("list blob empty or not canonical"));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/wire.md §4 (List tree): a thing cert round-trips; a path of another length, ids out of
    // order or a blob without certs is bad input.
    #[test]
    fn thing_cert_codec_spec_wire_4() {
        let list = ThingList { thing: Tid::from_bytes([1; 15]), ids: ListIds::Inline(vec![CommitId([2; 32]), CommitId([3; 32])]), salt: [4; 16] };
        let cert = ThingCert { rotation: CommitId([5; 32]), index: 7, siblings: vec![[6; 32]; LIST_TREE_DEPTH as usize], list: list.clone() };
        let blob = encode_list_blob(std::slice::from_ref(&cert));
        assert!(is_list_blob(&blob));
        assert_eq!(decode_list_blob(&blob).unwrap(), vec![cert.clone()]);
        let short = ThingCert { siblings: vec![[6; 32]; 3], ..cert.clone() };
        assert!(decode_list_blob(&encode_list_blob(&[short])).is_err());
        assert!(decode_list_blob(&encode_list_blob(&[])).is_err());
        let unsorted = ThingList { ids: ListIds::Inline(vec![CommitId([3; 32]), CommitId([2; 32])]), ..list };
        assert!(ThingList::from_value(&unsorted.to_value()).is_err());
    }
}
