//! Bundle import (spec/sync.md §11, spec/wire.md §12): osis-label's reader and importer (paths,
//! stamps and blob IDs verified as a server does) presented as a peer with no cursor, yielding
//! the client events a Sync would.

use crate::Error;
use crate::client::ClientEvent;
use crate::msg::Event;
use osis_core::BlobId;
use osis_label::{BundleEvent, BundleReader, Importer};
use std::collections::HashMap;
use std::io::Read;

pub struct BundleImport<R: Read> {
    reader: BundleReader<R>,
    importer: Importer,
    /// Blob bytes not yet named by an entry; the first entry carries them inline.
    blobs: HashMap<BlobId, Vec<u8>>,
}

impl<R: Read> BundleImport<R> {
    /// Checks the magic and the format record.
    pub fn new(r: R) -> Result<BundleImport<R>, Error> {
        Ok(BundleImport { reader: BundleReader::new(r)?, importer: Importer::new(), blobs: HashMap::new() })
    }

    /// The events of the next record (possibly none), `None` at the end. A broken frame ends the
    /// import with an error; a record the importer refuses (bad path, stamp, entry before its blob)
    /// yields a `PeerError` and the import goes on; unknown records are skipped.
    pub fn next_events(&mut self) -> Result<Option<Vec<ClientEvent>>, Error> {
        let Some(record) = self.reader.next_record()? else { return Ok(None) };
        let ev = match self.importer.import(record) {
            Err(e) => return Ok(Some(vec![ClientEvent::PeerError(e.into())])),
            Ok(None) => return Ok(Some(vec![])),
            Ok(Some(ev)) => ev,
        };
        let one = |label, e| vec![ClientEvent::Events { label, events: vec![e], cursor: None }];
        Ok(Some(match ev {
            BundleEvent::Path { label, steps } => vec![ClientEvent::PathSteps { label, steps: steps.into_iter().map(|(s, _)| s).collect(), more: false }],
            BundleEvent::Blob { id, blob } => {
                self.blobs.insert(id, blob);
                vec![]
            }
            BundleEvent::Add { label, blob, wrap, stamp } => one(label, Event::Added { blob_id: blob, blob: self.blobs.remove(&blob), wrap, stamp }),
            BundleEvent::Deleted { label, blob } => one(label, Event::Deleted(blob)),
            BundleEvent::TimedDelete { label, blob, at } => one(label, Event::Pending { blob_id: blob, at: at.0 }),
        }))
    }
}
