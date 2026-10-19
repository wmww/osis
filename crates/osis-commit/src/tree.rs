//! Chunk trees of linked header lists and frontiers (spec/wire.md §4 "Inline or link", §6).
//! Usable for any chunk tree; osis-label frames and stores the blobs behind the traits.

use crate::cbor::{as_idx, as_list, uint};
use crate::header::{Header, ListField};
use crate::tokens::Prefix;
use crate::Error;
use osis_core::format::{CHUNK_THRESHOLD, MAX_OBJECT_DEPTH, TREE_FANOUT, TREE_MAX_LEVEL};
use osis_core::{BlobId, ChunkParams, Limits, Link, Value, chunker};
use osis_crypto::{Secret32, link_hash, link_tree_hash};
use std::collections::HashMap;

/// Writes one blob (osis-label frames, encrypts and stores it) and returns its ID and key.
pub trait BlobSink {
    fn put(&mut self, prefix: &Prefix, plaintext: &[u8]) -> Result<(BlobId, [u8; 32]), Error>;
}

/// Returns a blob's decrypted, unpadded plaintext by link; `Error::Missing` if not held. The
/// content hash is checked by the caller.
pub trait BlobSource {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, Error>;
}

/// In-memory blobs for tests: blob ID = BLAKE3(salt || plaintext), key zero.
#[derive(Debug, Default)]
pub struct MemoryBlobs {
    pub blobs: HashMap<BlobId, (Prefix, Vec<u8>)>,
}

impl BlobSink for MemoryBlobs {
    fn put(&mut self, prefix: &Prefix, plaintext: &[u8]) -> Result<(BlobId, [u8; 32]), Error> {
        let mut h = osis_core::hash::Hasher::new();
        h.update(&prefix.salt);
        h.update(plaintext);
        let id = BlobId(h.finalize());
        self.blobs.insert(id, (prefix.clone(), plaintext.to_vec()));
        Ok((id, [0; 32]))
    }
}

impl BlobSource for MemoryBlobs {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, Error> {
        self.blobs.get(&link.blob).map(|b| b.1.clone()).ok_or(Error::Missing)
    }
}

fn put_link(sink: &mut dyn BlobSink, prefix: &mut dyn FnMut() -> Result<Prefix, Error>, hash: [u8; 32], plaintext: &[u8]) -> Result<Link, Error> {
    let (blob, key) = sink.put(&prefix()?, plaintext)?;
    Ok(Link { hash, blob, suite: 1, key })
}

/// Writes the chunk tree of `bytes` and returns its root link. `prefix` gives each blob's
/// prefix inputs (a fresh salt each call).
pub fn write_tree(bytes: &[u8], dedup: &Secret32, sink: &mut dyn BlobSink, prefix: &mut dyn FnMut() -> Result<Prefix, Error>) -> Result<Link, Error> {
    let mut links = Vec::new();
    let mut rest = bytes;
    for len in chunker::chunk_lengths(bytes, ChunkParams::FORMAT) {
        let (chunk, tail) = rest.split_at_checked(len).ok_or(Error::Build("chunker"))?;
        rest = tail;
        links.push(put_link(sink, prefix, link_hash(dedup, chunk), chunk)?);
    }
    let mut level = 1u64;
    loop {
        let mut nodes = Vec::new();
        let mut group: Vec<Link> = Vec::new();
        let n = links.len();
        for (i, l) in links.into_iter().enumerate() {
            let zero = l.hash.first() == Some(&0);
            group.push(l);
            if (group.len() >= 2 && zero) || group.len() >= TREE_FANOUT || i + 1 == n {
                let hashes: Vec<[u8; 32]> = group.iter().map(|l| l.hash).collect();
                let plain = osis_core::encode(&Value::List(vec![uint(level), Value::List(group.drain(..).map(Value::Link).collect())]));
                nodes.push(put_link(sink, prefix, link_tree_hash(dedup, level, &hashes), &plain)?);
            }
        }
        match nodes.as_slice() {
            [root] => return Ok(*root),
            [] => return Err(Error::Build("empty chunk tree")),
            _ => {}
        }
        if level >= TREE_MAX_LEVEL {
            return Err(Error::Build("chunk tree too deep"));
        }
        links = nodes;
        level += 1;
    }
}

fn read_node(link: &Link, level: Option<u64>, dedup: &Secret32, src: &mut dyn BlobSource, out: &mut Vec<u8>) -> Result<(), Error> {
    let plain = src.get(link)?;
    let v = osis_core::decode(&plain, &Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: plain.len() }).map_err(|_| Error::Corrupt)?;
    let [lv, children] = as_list(&v)? else { return Err(Error::Corrupt) };
    let lv = as_idx(lv)? as u64;
    if lv == 0 || lv > TREE_MAX_LEVEL || level.is_some_and(|l| l != lv) {
        return Err(Error::Corrupt);
    }
    let children = as_list(children)?
        .iter()
        .map(|c| match c {
            Value::Link(l) => Ok(*l),
            _ => Err(Error::Corrupt),
        })
        .collect::<Result<Vec<Link>, Error>>()?;
    if children.is_empty() || children.len() > TREE_FANOUT {
        return Err(Error::Corrupt);
    }
    let hashes: Vec<[u8; 32]> = children.iter().map(|l| l.hash).collect();
    if link_tree_hash(dedup, lv, &hashes) != link.hash {
        return Err(Error::Corrupt);
    }
    for c in &children {
        if lv == 1 {
            let chunk = src.get(c)?;
            if link_hash(dedup, &chunk) != c.hash {
                return Err(Error::Corrupt);
            }
            out.extend_from_slice(&chunk);
        } else {
            read_node(c, Some(lv - 1), dedup, src, out)?;
        }
    }
    Ok(())
}

/// Reads the bytes of the chunk tree under `root`, checking every content hash.
pub fn read_tree(root: &Link, dedup: &Secret32, src: &mut dyn BlobSource) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    read_node(root, None, dedup, src, &mut out)?;
    Ok(out)
}

impl Header {
    /// Fetches and fills every linked list, keyed by the dedup secret of the header's `actor`.
    /// A linked list at or below `CHUNK_THRESHOLD` is bad input.
    pub fn resolve(&mut self, src: &mut dyn BlobSource, actor_dedup: &Secret32) -> Result<(), Error> {
        for f in ListField::ALL {
            let Some(link) = self.links.get(f).copied() else { continue };
            if !self.list_is_empty(f) {
                continue;
            }
            let bytes = read_tree(&link, actor_dedup, src)?;
            if bytes.len() <= CHUNK_THRESHOLD {
                return Err(Error::Malformed("linked list at or below CHUNK_THRESHOLD"));
            }
            let v = osis_core::decode(&bytes, &Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: bytes.len() })?;
            if f != ListField::Frontier && !matches!(v, Value::List(_)) {
                return Err(Error::Malformed("linked list"));
            }
            self.set_list(f, &v)?;
        }
        Ok(())
    }
}
