//! Bundle import (spec/sync.md §11, spec/wire.md §12): a bundle file read as a peer with no
//! cursor, yielding the client events a Sync would. Paths and stamps are verified as a server
//! does. Record decoding is part of the osis-label coupling (`label`): switch to its reader when
//! that crate lands.

use crate::Error;
use crate::client::ClientEvent;
use crate::dec::{self, Fields};
use crate::frame::FrameDecoder;
use crate::label::{self, ClaimSet, StepInfo};
use crate::msg::{Event, MAX_STEP_BYTES};
use osis_core::format::{MAX_BLOB, MAX_MESSAGE};
use osis_core::{BlobId, LabelId, Limits, Value, cbor};
use osis_crypto::Domain;
use std::collections::{BTreeMap, HashMap};

pub const MAGIC: &[u8; 8] = b"osisbndl";
pub const BUNDLE_FORMAT: u64 = 1;

/// Streaming bundle importer. Feed bytes with `push`; call `finish` at the end.
#[derive(Default)]
pub struct BundleImport {
    magic: Vec<u8>,
    decoder: FrameDecoder,
    header: bool,
    /// Write keys of every step of each label's verified path (stamps accepted under any of them
    /// stay valid, spec/sync.md §5).
    writers: BTreeMap<LabelId, Vec<[u8; 32]>>,
    /// Blob bytes not yet used by a valid entry.
    blobs: HashMap<BlobId, Vec<u8>>,
}

impl BundleImport {
    pub fn new() -> BundleImport {
        BundleImport::default()
    }

    /// Takes the next bytes of the file. A broken frame or header ends the import with an error;
    /// a bad record is skipped with a `PeerError` event; records of unknown kind are skipped.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<ClientEvent>, Error> {
        if self.magic.len() < MAGIC.len() {
            let n = (MAGIC.len() - self.magic.len()).min(bytes.len());
            let (head, rest) = bytes.split_at(n);
            self.magic.extend_from_slice(head);
            bytes = rest;
            if !MAGIC.starts_with(&self.magic) {
                return Err(Error::Malformed("bundle magic"));
            }
        }
        self.decoder.push(bytes);
        let mut out = Vec::new();
        while let Some(frame) = self.decoder.next_frame()? {
            let v = cbor::decode(&frame, &Limits { max_depth: 4, max_bytes: MAX_MESSAGE })?;
            if !self.header {
                let mut f = Fields::exact(v, 2, "bundle header")?;
                if f.uint()? != 0 || f.uint()? != BUNDLE_FORMAT {
                    return Err(Error::Malformed("bundle header"));
                }
                self.header = true;
                continue;
            }
            if let Err(e) = self.record(v, &mut out) {
                out.push(ClientEvent::PeerError(e));
            }
        }
        Ok(out)
    }

    /// Checks that the file ended on a record boundary.
    pub fn finish(&self) -> Result<(), Error> {
        if self.magic.len() < MAGIC.len() || !self.header || self.decoder.pending() > 0 {
            return Err(Error::Malformed("bundle truncated"));
        }
        Ok(())
    }

    fn record(&mut self, v: Value, out: &mut Vec<ClientEvent>) -> Result<(), Error> {
        let Value::List(items) = &v else { return Err(Error::Malformed("bundle record")) };
        let kind = match items.first() {
            Some(Value::Int(k)) if *k >= 0 => *k as u64,
            _ => return Err(Error::Malformed("bundle record")),
        };
        let n = match kind {
            1 => 3,
            2 => 2,
            3 => 5,
            4 => 3,
            5 => 4,
            _ => return Ok(()),
        };
        let mut f = Fields::exact(v, n, "bundle record")?;
        f.next()?;
        match kind {
            1 => {
                let label = LabelId(f.fixed()?);
                let mut steps: Vec<StepInfo> = Vec::new();
                for s in f.list(1, usize::MAX, "bundle path")? {
                    let mut p = Fields::exact(s, 2, "bundle step")?;
                    let step = StepInfo::parse(&p.bytes(MAX_STEP_BYTES)?)?;
                    if let Some(cs) = p.opt()? {
                        let cs = dec::bytes(cs, MAX_MESSAGE, "claim set")?;
                        if osis_core::hash::hash(&cs) != step.claims_hash {
                            return Err(Error::Malformed("bundle claim set hash"));
                        }
                        ClaimSet::parse(&cs)?;
                    }
                    let ok = step.label == label
                        && match steps.last() {
                            None => step.is_valid_genesis(),
                            Some(parent) => parent.is_parent_of(&step),
                        };
                    if !ok {
                        return Err(Error::Malformed("bundle path"));
                    }
                    steps.push(step);
                }
                self.writers.insert(label, steps.iter().map(|s| s.write).collect());
                out.push(ClientEvent::PathSteps { label, steps: steps.into_iter().map(|s| s.bytes).collect(), more: false });
            }
            2 => {
                let blob = f.bytes(MAX_BLOB)?;
                self.blobs.insert(osis_crypto::blob_id(&blob), blob);
            }
            3 => {
                let label = LabelId(f.fixed()?);
                let blob_id = BlobId(f.fixed()?);
                let wrap = f.fixed()?;
                let stamp = f.opt()?.map(|v| dec::fixed(v, "stamp")).transpose()?;
                let writers = self.writers.get(&label).ok_or(Error::Malformed("bundle entry before its path"))?;
                let digest = label::entry_digest(&label, &blob_id, &wrap);
                if let Some(s) = &stamp
                    && !writers.iter().any(|w| label::verify(w, Domain::Upload, &digest, s))
                {
                    return Err(Error::Malformed("bundle stamp"));
                }
                let blob = self.blobs.remove(&blob_id);
                push_event(out, label, Event::Added { blob_id, blob, wrap, stamp });
            }
            4 => {
                let label = LabelId(f.fixed()?);
                push_event(out, label, Event::Deleted(BlobId(f.fixed()?)));
            }
            _ => {
                let label = LabelId(f.fixed()?);
                let blob_id = BlobId(f.fixed()?);
                push_event(out, label, Event::Pending { blob_id, at: f.uint()? });
            }
        }
        f.end()
    }
}

/// Appends to the last Events event when it is for the same label.
fn push_event(out: &mut Vec<ClientEvent>, label: LabelId, e: Event) {
    if let Some(ClientEvent::Events { label: l, events, cursor: None }) = out.last_mut()
        && *l == label
    {
        events.push(e);
        return;
    }
    out.push(ClientEvent::Events { label, events: vec![e], cursor: None });
}
