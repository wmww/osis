//! Bundle import (spec/sync-streams.md §6, spec/wire.md §12): osis-label's reader and importer (paths,
//! stamps and blob IDs verified as a store does), yielding paths and log events as a peer's
//! stream would, with no cursor.

use crate::Error;
use crate::msg::Event;
use crate::SyncId;
use osis_base::BlobId;
use osis_label::Step;
use osis_label::{BundleEvent, BundleReader, Importer};
use std::collections::HashMap;
use std::io::Read;

/// What one bundle record gives.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one record at a time; boxing buys nothing
pub enum Imported {
    /// A sync ID's registration path, from its genesis step.
    Path { sync_id: SyncId, steps: Vec<Step> },
    /// One log event of a sync ID.
    Event { sync_id: SyncId, event: Event },
    /// A record the importer refused (bad path, stamp, entry before its blob).
    Refused(Error),
}

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

    /// What the next record gives (possibly nothing), `None` at the end. A broken frame ends the
    /// import with an error; a refused record yields `Refused` and the import goes on; unknown
    /// records are skipped.
    #[allow(clippy::should_implement_trait)] // fallible: an iterator of results would hide the end
    pub fn next(&mut self) -> Result<Option<Option<Imported>>, Error> {
        let Some(record) = self.reader.next_record()? else { return Ok(None) };
        let ev = match self.importer.import(record) {
            Err(e) => return Ok(Some(Some(Imported::Refused(e.into())))),
            Ok(None) => return Ok(Some(None)),
            Ok(Some(ev)) => ev,
        };
        Ok(Some(match ev {
            BundleEvent::Path { label, steps } => Some(Imported::Path { sync_id: label, steps: steps.into_iter().map(|(s, _)| s).collect() }),
            BundleEvent::Blob { id, blob } => {
                self.blobs.insert(id, blob);
                None
            }
            BundleEvent::Add { label, blob, wrap, stamp } => Some(Imported::Event { sync_id: label, event: Event::Added { blob_id: blob, blob: self.blobs.remove(&blob), wrap, stamp } }),
            BundleEvent::Deleted { label, blob } => Some(Imported::Event { sync_id: label, event: Event::Deleted(blob) }),
        }))
    }
}
