//! Page storage plugs for paged fragments (spec/crdt.md §8, spec/wire.md §6). osis-blob and the
//! node implement them over blobs; `MemoryPages` serves tests.

use osis_base::format::{MAX_PAGE_ITEMS, PAGE_TARGET, TREE_FANOUT};
use osis_base::{BlobId, ChunkParams, Classified, ErrorClass, Link};
use std::cell::Cell;
use std::collections::HashMap;
use crate::error::Error;
use crate::fragment::Fragment;
use crate::paging::{Paths, Step};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageError {
    /// The page is not available locally. Local (pages are fetched before a commit applies).
    Missing,
    /// The page failed its content hash or decryption. BadInput.
    Corrupt,
    /// The page's link or blob names other delete keys than its delta lists (spec/crypto.md §7
    /// Checked keys). BadInput.
    Keys,
    /// Storage failure. Local.
    Storage,
}

osis_base::impl_error!(PageError {
    Missing => ("missing"),
    Corrupt => ("content hash or decryption failed"),
    Keys => ("a page framed for other delete keys than its delta lists"),
    Storage => ("storage failure"),
});

impl Classified for PageError {
    fn class(&self) -> ErrorClass {
        match self {
            PageError::Corrupt | PageError::Keys => ErrorClass::BadInput,
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
    /// Items per page and per root fragment at most (`MAX_PAGE_ITEMS`); `usize::MAX`: unchecked.
    pub max_items: usize,
}

impl PageParams {
    pub const FORMAT: PageParams = PageParams { target: PAGE_TARGET, cut: ChunkParams::FORMAT, fanout: TREE_FANOUT, max_items: MAX_PAGE_ITEMS };
    /// Never pages: relay-only deltas (spec/commits.md §2), bounded by the blob alone.
    pub const UNPAGED: PageParams = PageParams { target: usize::MAX, max_items: usize::MAX, ..PageParams::FORMAT };

    /// What the node's page plugs page with: `FORMAT`, or on this thread the parameters a test
    /// set (`set_test`), so an engine test reaches deep link trees with small states.
    pub fn wire() -> PageParams {
        TEST_PARAMS.with(Cell::get).unwrap_or(PageParams::FORMAT)
    }

    /// Tests: this thread's page plugs page with `p` (`None`: `FORMAT`) until the guard drops,
    /// which sets back what was set. Bind the guard before the worlds built under it: locals drop
    /// in reverse, so they drop (and run their last checks) under the pages they were written
    /// with; a state read under other parameters fails the tree rule.
    #[doc(hidden)]
    pub fn set_test(p: Option<PageParams>) -> TestPages {
        TestPages(TEST_PARAMS.with(|c| c.replace(p)))
    }
}

/// `PageParams::set_test` in force until dropped.
#[doc(hidden)]
#[must_use = "the parameters are set back when this drops"]
pub struct TestPages(Option<PageParams>);

impl Drop for TestPages {
    fn drop(&mut self) {
        TEST_PARAMS.with(|c| c.set(self.0));
    }
}

thread_local! {
    static TEST_PARAMS: Cell<Option<PageParams>> = const { Cell::new(None) };
}

/// The page plug of a delta that is never paged (relay-only deltas, spec/commits.md §2):
/// encodes every array inline; a link to a page is bad input.
#[derive(Debug, Default, Clone, Copy)]
pub struct Unpaged;

impl PageSink for Unpaged {
    fn put(&mut self, _: &[u8]) -> Result<Link, PageError> {
        Err(PageError::Corrupt)
    }
    fn params(&self) -> PageParams {
        PageParams::UNPAGED
    }
}

/// A state held whole: no collection kept as pages.
impl PageWalk for Unpaged {
    fn pages(&mut self, _: &[Step]) -> Result<usize, Error> {
        Err(Error::Mismatch("a whole state has no pages"))
    }
    fn page(&mut self, _: &[Step], _: usize) -> Result<StoredPage, Error> {
        Err(Error::Mismatch("a whole state has no pages"))
    }
    fn keyed(&mut self, _: &[Step]) -> Result<KeyedPath, Error> {
        Err(Error::Mismatch("a whole state has no pages"))
    }
    fn page_of(&mut self, _: &[Step], _: &crate::Dot) -> Result<StoredPage, Error> {
        Err(Error::Mismatch("a whole state has no pages"))
    }
    fn dots_of(&mut self, _: &[Step], _: &osis_base::Value) -> Result<Vec<crate::Dot>, Error> {
        Err(Error::Mismatch("a whole state has no pages"))
    }
}

impl PageSource for Unpaged {
    fn get(&mut self, _: &Link) -> Result<Vec<u8>, PageError> {
        Err(PageError::Corrupt)
    }
    fn params(&self) -> PageParams {
        PageParams::UNPAGED
    }
}

/// Writes one page or link page (its canonical plaintext) as a blob and returns its link.
pub trait PageSink {
    fn put(&mut self, plaintext: &[u8]) -> Result<Link, PageError>;
    fn params(&self) -> PageParams {
        PageParams::wire()
    }
}

/// Returns a page's plaintext by link, content hash verified.
pub trait PageSource {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, PageError>;
    fn params(&self) -> PageParams {
        PageParams::wire()
    }
}

/// A state kept as a skeleton and pages of its large collections (the node's paged states,
/// notes/engine-paged.md), as it is stored: what `Paged` reads a page at a time. What the reader
/// holds is what it asked for last: a store bounding a read charges each page served.
pub trait PageWalk {
    /// How many pages the collection at `path` (steps from the root) is kept as.
    fn pages(&mut self, path: &[Step]) -> Result<usize, Error>;
    /// Its page `i` as stored: a run of its root elements, all above page `i - 1`'s, every
    /// collection kept as pages below them reduced (`Fragment::reduced`). A record holding only
    /// such content may be missing from it.
    fn page(&mut self, path: &[Step], i: usize) -> Result<StoredPage, Error>;
    /// The path to the collection at `path` with each entry step's key and creation
    /// (`Fragment::wrap`): what gives a record holding only paged content back.
    fn keyed(&mut self, path: &[Step]) -> Result<KeyedPath, Error>;
    /// The page of the collection at `path` holding element `d` (the last whose first element is
    /// at or below it), as `page` serves it.
    fn page_of(&mut self, path: &[Step], d: &crate::Dot) -> Result<StoredPage, Error>;
    /// The elements of the map or set at `path` found by key or value `k`
    /// (`Fragment::index_values`): a superset, in any order.
    fn dots_of(&mut self, path: &[Step], k: &osis_base::Value) -> Result<Vec<crate::Dot>, Error>;
}

/// A path with the keys and creations of its entry steps (`Fragment::wrap`).
pub type KeyedPath = Vec<(Step, Option<osis_base::Value>, Option<crate::Stamp>)>;

/// A page of a collection as stored: its elements from dot `lo` (`None`: the first page) to
/// `hi` (`None`: the last), every record of a dot on one page.
pub struct StoredPage {
    pub lo: Option<crate::Dot>,
    pub hi: Option<crate::Dot>,
    pub frag: Fragment,
}

/// A stored state read a page at a time (`page_view`: `encode_paged_snapshot`, `sweep_paged`,
/// `each_piece`): `skeleton`, the state with its collections at `paths` reduced
/// (`Fragment::reduced`), their pages, and the writes `gone` names (by origin dot), which the
/// reader leaves out (a snapshot does not carry them, spec/crdt.md §4.7, §8).
pub struct Paged<'a> {
    pub skeleton: &'a Fragment,
    pub paths: &'a Paths,
    pub pages: &'a mut dyn PageWalk,
    pub gone: &'a dyn Fn(&crate::Dot) -> bool,
}

/// In-memory pages for tests: the link hash is the unkeyed BLAKE3 of the plaintext, the blob ID
/// a counter, the key zero.
#[derive(Debug)]
pub struct MemoryPages {
    /// Plaintexts by hash.
    pub pages: HashMap<[u8; 32], Vec<u8>>,
    /// Hashes of the plaintexts in the order they were put.
    pub written: Vec<[u8; 32]>,
    next: u64,
    params: PageParams,
    /// The delete keys its links name, as a framing's would (spec/crypto.md §7 Page links).
    pub del: osis_base::Del,
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
        MemoryPages { pages: HashMap::new(), written: Vec::new(), next: 0, params, del: osis_base::Del::NONE }
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
        self.written.push(hash);
        Ok(Link { hash, blob: BlobId(blob), suite: 1, key: [0; 32], salt: [0; 16], del: self.del })
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
