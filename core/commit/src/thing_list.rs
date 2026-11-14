//! A rotation's thing lists and list blobs (spec/wire.md §4, List tree; spec/permissions.md §5.5):
//! `ThingList := [tid, [commit_id*] | LINK, salt]`, `ThingCert := [rotation_id, index, [hash*],
//! ThingList]`, `ListBlobPlaintext := ["list", [ThingCert+]]`. Folding a cert to its rotation's
//! `list_root` is osis-perm's (`ListPath`).

use crate::cbor::{item, strictly_ascending};
use crate::header::LIMITS;
use crate::Error;
use osis_base::cbor::{Item, put_array, put_bytes, put_link, put_text, put_uint};
use osis_base::format::{CHUNK_THRESHOLD, LIST_TREE_DEPTH};
use osis_base::{CommitId, Link, Tid};

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

impl ThingList {
    /// The canonical bytes its leaf hashes (`osis_perm::epochs::list_leaf`).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.put(&mut out);
        out
    }

    fn put(&self, out: &mut Vec<u8>) {
        put_array(out, 3);
        put_bytes(out, self.thing.as_bytes());
        match &self.ids {
            ListIds::Inline(ids) => {
                put_array(out, ids.len());
                ids.iter().for_each(|c| put_bytes(out, &c.0));
            }
            ListIds::Linked(l) => put_link(out, l),
        }
        put_bytes(out, &self.salt);
    }

    fn read(v: Item) -> Result<ThingList, Error> {
        let Some([t, ids, salt]) = item::list(v)?.tuple() else { return Err(Error::Malformed("thing list arity")) };
        let ids = match ids.as_link() {
            Some(l) => ListIds::Linked(l),
            None => {
                if ids.bytes().len() > CHUNK_THRESHOLD {
                    return Err(Error::Malformed("inline thing list above CHUNK_THRESHOLD"));
                }
                let ids = item::list(ids)?.map(|c| item::bytes(c).map(CommitId)).collect::<Result<Vec<_>, _>>()?;
                if !strictly_ascending(&ids, |c| *c) {
                    return Err(Error::Malformed("thing list ids not sorted and distinct"));
                }
                ListIds::Inline(ids)
            }
        };
        Ok(ThingList { thing: item::tid(t)?, ids, salt: item::bytes(salt)? })
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
    fn put(&self, out: &mut Vec<u8>) {
        put_array(out, 4);
        put_bytes(out, &self.rotation.0);
        put_uint(out, self.index);
        put_array(out, self.siblings.len());
        self.siblings.iter().for_each(|h| put_bytes(out, h));
        self.list.put(out);
    }

    fn read(v: Item) -> Result<ThingCert, Error> {
        let Some([r, i, sib, list]) = item::list(v)?.tuple() else { return Err(Error::Malformed("thing cert arity")) };
        let siblings = item::list(sib)?.map(item::bytes).collect::<Result<Vec<[u8; 32]>, _>>()?;
        let index = item::uint(i)?;
        if siblings.len() != LIST_TREE_DEPTH as usize || index >> LIST_TREE_DEPTH != 0 {
            return Err(Error::Malformed("thing cert path"));
        }
        Ok(ThingCert { rotation: CommitId(item::bytes(r)?), index, siblings, list: ThingList::read(list)? })
    }
}

const LIST_TAG: &str = "list";

/// A list blob's plaintext (spec/wire.md §4): one or more thing certs.
pub fn encode_list_blob(certs: &[ThingCert]) -> Vec<u8> {
    let mut out = Vec::new();
    put_array(&mut out, 2);
    put_text(&mut out, LIST_TAG);
    put_array(&mut out, certs.len());
    certs.iter().for_each(|c| c.put(&mut out));
    out
}

/// Reads a list blob's plaintext: canonical, at least one cert.
pub fn decode_list_blob(plain: &[u8]) -> Result<Vec<ThingCert>, Error> {
    let Some([tag, certs]) = item::list(Item::parse(plain, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("list blob arity")) };
    if tag.as_str() != Some(LIST_TAG) {
        return Err(Error::Malformed("list blob tag"));
    }
    let certs = item::list(certs)?.map(ThingCert::read).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(Error::Malformed("list blob empty"));
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
        assert_eq!(decode_list_blob(&blob).unwrap(), vec![cert.clone()]);
        let short = ThingCert { siblings: vec![[6; 32]; 3], ..cert.clone() };
        assert!(decode_list_blob(&encode_list_blob(&[short])).is_err());
        assert!(decode_list_blob(&encode_list_blob(&[])).is_err());
        let unsorted = ThingList { ids: ListIds::Inline(vec![CommitId([3; 32]), CommitId([2; 32])]), ..list.clone() };
        assert!(ThingList::read(Item::parse(&unsorted.encode(), &LIMITS).unwrap()).is_err());
        // a linked list round-trips; a leaf's bytes are the canonical value `[tid, LINK, salt]`
        let link = Link { hash: [8; 32], blob: osis_base::BlobId([9; 32]), suite: 1, key: [0; 32], salt: [0; 16], del: osis_base::Del::NONE };
        let linked = ThingCert { list: ThingList { ids: ListIds::Linked(link), ..list }, ..cert };
        assert_eq!(decode_list_blob(&encode_list_blob(std::slice::from_ref(&linked))).unwrap(), vec![linked.clone()]);
        let v = osis_base::Value::List(vec![osis_base::Value::bytes(&[1; 15]), osis_base::Value::link(link), osis_base::Value::bytes(&[4; 16])]);
        assert_eq!(linked.list.encode(), osis_base::encode(&v));
    }
}
