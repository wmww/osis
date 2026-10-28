//! Page storage plugs for paged fragments (spec/crdt.md §8, spec/wire.md §6). osis-label and the
//! node implement them over blobs; `MemoryPages` serves tests.

use osis_base::format::{PAGE_TARGET, TREE_FANOUT};
use osis_base::{BlobId, ChunkParams, Classified, ErrorClass, Link};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageError {
    /// The page is not available locally. Local (pages are fetched before a commit applies).
    Missing,
    /// The page failed its content hash or decryption. BadInput.
    Corrupt,
    /// Storage failure. Local.
    Storage,
}

osis_base::impl_error!(PageError {
    Missing => ("missing"),
    Corrupt => ("content hash or decryption failed"),
    Storage => ("storage failure"),
});

impl Classified for PageError {
    fn class(&self) -> ErrorClass {
        match self {
            PageError::Corrupt => ErrorClass::BadInput,
            PageError::Missing | PageError::Storage => ErrorClass::Local,
        }
    }
}

/// Paging parameters (spec/crdt.md §8, spec/wire.md §6). Only `FORMAT` is valid on the wire;
/// tests shrink them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageParams {
    /// An element array above this many bytes is paged; a link list above it goes to link pages.
    pub target: usize,
    /// Page boundaries.
    pub cut: ChunkParams,
    /// Links per link page at most.
    pub fanout: usize,
}

impl PageParams {
    pub const FORMAT: PageParams = PageParams { target: PAGE_TARGET, cut: ChunkParams::FORMAT, fanout: TREE_FANOUT };
}

/// Writes one page or link page (its canonical plaintext) as a blob and returns its link.
pub trait PageSink {
    fn put(&mut self, plaintext: &[u8]) -> Result<Link, PageError>;
    fn params(&self) -> PageParams {
        PageParams::FORMAT
    }
}

/// Returns a page's plaintext by link, content hash verified.
pub trait PageSource {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, PageError>;
    fn params(&self) -> PageParams {
        PageParams::FORMAT
    }
}

/// In-memory pages for tests: the link hash is the unkeyed BLAKE3 of the plaintext, the blob ID
/// a counter, the key zero.
#[derive(Debug)]
pub struct MemoryPages {
    pages: HashMap<[u8; 32], Vec<u8>>,
    next: u64,
    params: PageParams,
}

impl Default for MemoryPages {
    fn default() -> MemoryPages {
        MemoryPages::with_params(PageParams::FORMAT)
    }
}

impl MemoryPages {
    pub fn new() -> MemoryPages {
        MemoryPages::default()
    }
    /// With non-format parameters (tests).
    pub fn with_params(params: PageParams) -> MemoryPages {
        MemoryPages { pages: HashMap::new(), next: 0, params }
    }
    pub fn len(&self) -> usize {
        self.pages.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }
}

impl PageSink for MemoryPages {
    fn put(&mut self, plaintext: &[u8]) -> Result<Link, PageError> {
        let hash = osis_base::hash::hash(plaintext);
        self.next += 1;
        let mut blob = [0u8; 32];
        for (b, x) in blob.iter_mut().zip(self.next.to_le_bytes()) {
            *b = x;
        }
        self.pages.insert(hash, plaintext.to_vec());
        Ok(Link { hash, blob: BlobId(blob), suite: 1, key: [0; 32] })
    }
    fn params(&self) -> PageParams {
        self.params
    }
}

impl PageSource for MemoryPages {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, PageError> {
        let page = self.pages.get(&link.hash).ok_or(PageError::Missing)?;
        if osis_base::hash::hash(page) != link.hash {
            return Err(PageError::Corrupt);
        }
        Ok(page.clone())
    }
    fn params(&self) -> PageParams {
        self.params
    }
}
