//! Chunk trees of linked header lists and frontiers (spec/wire.md §4 "Inline or link", §6).
//! Usable for any chunk tree; osis-label frames and stores the blobs behind the traits.

use crate::cbor::{as_idx, as_list, uint};
use crate::header::{Header, ListField};
use crate::tokens::Prefix;
use crate::Error;
use osis_core::format::{CHUNK_MIN, CHUNK_THRESHOLD, MAX_OBJECT_DEPTH, TREE_FANOUT, TREE_MAX_LEVEL};
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

/// Default local bound on a resolved header list (`Header::resolve`): a node policy, not a
/// format limit (spec/requirements.md: a change has no size limit).
pub const MAX_LIST_BYTES: usize = 64 * CHUNK_THRESHOLD;

/// Tree reader state. Links may repeat (identical chunks share a blob), so the reader is
/// bounded by chunk count instead: every chunk but the last is at least `CHUNK_MIN` bytes, so
/// at most `max / CHUNK_MIN + 1` chunks are visited.
struct Reader<'a> {
    dedup: &'a Secret32,
    src: &'a mut dyn BlobSource,
    out: Vec<u8>,
    max: usize,
    chunks: usize,
    /// Length of the last chunk read.
    last: Option<usize>,
}

fn read_node(r: &mut Reader<'_>, link: &Link, level: Option<u64>) -> Result<(), Error> {
    let dedup = r.dedup;
    let plain = r.src.get(link)?;
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
        if lv > 1 {
            read_node(r, c, Some(lv - 1))?;
            continue;
        }
        if r.last.is_some_and(|l| l < CHUNK_MIN) {
            return Err(Error::Malformed("chunk tree: a non-final chunk below CHUNK_MIN"));
        }
        r.chunks += 1;
        if r.chunks > r.max / CHUNK_MIN + 1 {
            return Err(Error::Storage("chunk tree above the local size bound"));
        }
        let chunk = r.src.get(c)?;
        if link_hash(dedup, &chunk) != c.hash {
            return Err(Error::Corrupt);
        }
        if chunk.is_empty() {
            return Err(Error::Malformed("chunk tree: empty chunk"));
        }
        if r.out.len().saturating_add(chunk.len()) > r.max {
            return Err(Error::Storage("chunk tree above the local size bound"));
        }
        r.last = Some(chunk.len());
        r.out.extend_from_slice(&chunk);
    }
    Ok(())
}

/// Reads the bytes of the chunk tree under `root`, checking every content hash. A non-final
/// chunk below `CHUNK_MIN` or an empty chunk is bad input; output above `max` bytes is refused
/// (a local bound), which also bounds the chunks visited.
pub fn read_tree(root: &Link, dedup: &Secret32, src: &mut dyn BlobSource, max: usize) -> Result<Vec<u8>, Error> {
    let mut r = Reader { dedup, src, out: Vec::new(), max, chunks: 0, last: None };
    read_node(&mut r, root, None)?;
    Ok(r.out)
}


impl Header {
    /// Fetches and fills every linked list, keyed by the dedup secret of the header's `actor`.
    /// A linked list at or below `CHUNK_THRESHOLD` is bad input; one above `max` bytes (a local
    /// bound such as [`MAX_LIST_BYTES`]) is not resolved (`Storage`, Local).
    pub fn resolve(&mut self, src: &mut dyn BlobSource, actor_dedup: &Secret32, max: usize) -> Result<(), Error> {
        for f in ListField::ALL {
            let Some(link) = self.links.get(f).copied() else { continue };
            if !self.list_is_empty(f) {
                continue;
            }
            let bytes = read_tree(&link, actor_dedup, src, max)?;
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
