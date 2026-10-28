//! Linked header lists and frontiers (spec/wire.md §4 "Inline or link"): chunk trees written and
//! read through the tree module, over blob plugs that take prefix inputs and return plaintext
//! (osis-label frames, encrypts and stores the blobs).

use crate::header::{Header, ListField};
use crate::keys::Prefix;
use crate::tree::{self, LinkSource, TreeSink, node_plaintext};
use crate::Error;
use osis_base::format::{CHUNK_THRESHOLD, MAX_OBJECT_DEPTH};
use osis_base::{BlobId, ChunkParams, Limits, Link, Value};
use osis_crypto::{Secret32, link_hash};
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
        let mut h = osis_base::hash::Hasher::new();
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

/// Tree sink over a `BlobSink`: each blob gets fresh prefix inputs from `prefix`.
struct ListSink<'a> {
    dedup: &'a Secret32,
    sink: &'a mut dyn BlobSink,
    prefix: &'a mut dyn FnMut() -> Result<Prefix, Error>,
}

impl ListSink<'_> {
    fn put(&mut self, hash: [u8; 32], plaintext: &[u8]) -> Result<Link, Error> {
        let (blob, key) = self.sink.put(&(self.prefix)()?, plaintext)?;
        Ok(Link { hash, blob, suite: 1, key })
    }
}

impl TreeSink for ListSink<'_> {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, Error> {
        self.put(link_hash(self.dedup, bytes), bytes)
    }
    fn node(&mut self, level: u64, kids: &[tree::Kid]) -> Result<Link, Error> {
        self.put(tree::node_hash(self.dedup, level, kids), &node_plaintext(level, kids)?)
    }
}

struct ListSource<'a>(&'a mut dyn BlobSource);

impl LinkSource for ListSource<'_> {
    fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, Error> {
        self.0.get(link)
    }
}

/// Writes the chunk tree of a header list's bytes and returns its root link (empty input: one
/// empty chunk). `prefix` gives each blob's prefix inputs (a fresh salt each call).
pub fn write_list(bytes: &[u8], dedup: &Secret32, sink: &mut dyn BlobSink, prefix: &mut dyn FnMut() -> Result<Prefix, Error>) -> Result<Link, Error> {
    tree::write_tree(&mut ListSink { dedup, sink, prefix }, ChunkParams::FORMAT, bytes)
}

/// Default local bound on a resolved header list (`Header::resolve`): a node policy, not a
/// format limit (spec/requirements.md: a change has no size limit).
pub const MAX_LIST_BYTES: usize = 64 * CHUNK_THRESHOLD;

/// Reads the bytes of a header list's chunk tree under `root`, checking every content hash. A
/// non-final chunk below `CHUNK_MIN` is bad input; output above `max` bytes is refused
/// (`TooLarge`, a local bound), which also bounds the chunks visited.
pub fn read_list(root: &Link, dedup: &Secret32, src: &mut dyn BlobSource, max: usize) -> Result<Vec<u8>, Error> {
    tree::read_tree(root, dedup, &mut ListSource(src), ChunkParams::FORMAT, max)
}

impl Header {
    /// Fetches and fills every linked list, keyed by the dedup secret of the header's `actor`.
    /// A linked list at or below `CHUNK_THRESHOLD` is bad input; one above `max` bytes (a local
    /// bound such as [`MAX_LIST_BYTES`]) is not resolved (`TooLarge`, Local).
    pub fn resolve(&mut self, src: &mut dyn BlobSource, actor_dedup: &Secret32, max: usize) -> Result<(), Error> {
        for f in ListField::ALL {
            let Some(link) = self.links.get(f).copied() else { continue };
            if !self.list_is_empty(f) {
                continue;
            }
            let bytes = read_list(&link, actor_dedup, src, max)?;
            if bytes.len() <= CHUNK_THRESHOLD {
                return Err(Error::Malformed("linked list at or below CHUNK_THRESHOLD"));
            }
            let v = osis_base::decode(&bytes, &Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: bytes.len() })?;
            if f != ListField::Frontier && !matches!(v, Value::List(_)) {
                return Err(Error::Malformed("linked list"));
            }
            self.set_list(f, &v)?;
        }
        Ok(())
    }
}
