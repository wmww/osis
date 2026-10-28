//! File bundles (spec/sync.md §11; spec/wire.md §12): export of the labels this node holds
//! entries of (registration path, blobs, entries with wraps and stamps); import as a peer with
//! no cursor through osis-proto's `BundleImport`.

use super::SyncEngine;
use crate::error::{Error, Result};
use osis_base::{BlobId, LabelId};
use osis_label::{BundleWriter, Record};
use osis_proto::ClientEvent;
use std::collections::BTreeSet;

impl SyncEngine {
    /// A bundle of `labels`: each label's path to the newest head this node knows of, then
    /// every entry it knows under it with its blob (each blob once).
    pub fn export_bundle(&mut self, labels: &[LabelId]) -> Result<Vec<u8>> {
        let mut w = BundleWriter::new(Vec::new())?;
        let mut sent: BTreeSet<BlobId> = BTreeSet::new();
        for l in labels {
            let Some(g) = self.group_of(l) else { continue };
            if let Some(gl) = self.group_label(&g, l) {
                let head = self.state.heads.iter().filter(|((_, x), _)| x == l).map(|(_, h)| h.id()).find(|h| gl.steps.contains_key(h)).or_else(|| gl.tips().into_iter().next());
                if let Some(head) = head {
                    let steps = super::open::path_to(&gl.steps, head).ok_or(Error::Corrupt("step cycle"))?.into_iter().cloned().collect();
                    w.record(&Record::Path { label: *l, steps })?;
                }
            }
            let entries: Vec<(BlobId, [u8; osis_crypto::WRAP_LEN], Option<osis_crypto::Signature>)> = self.state.label_entries(l).map(|(b, e)| (b, e.wrap, e.stamp)).collect();
            for (b, wrap, stamp) in entries {
                let Some(bytes) = self.engine.blob(&b)? else { continue };
                if sent.insert(b) {
                    w.record(&Record::Blob(bytes))?;
                }
                w.record(&Record::Entry { label: *l, blob: b, wrap, stamp })?;
            }
        }
        Ok(w.finish()?)
    }

    /// Imports a bundle as a peer with no cursor (spec/sync.md §11): paths recorded (by an
    /// admin), entries opened and applied like downloaded ones.
    pub fn import_bundle(&mut self, bytes: &[u8]) -> Result<Vec<super::Action>> {
        let mut out = Vec::new();
        let mut imp = osis_proto::bundle::BundleImport::new(bytes).map_err(|_| Error::BadInput("bundle"))?;
        while let Some(evs) = imp.next_events().map_err(|_| Error::BadInput("bundle frame"))? {
            for e in evs {
                match e {
                    ClientEvent::PathSteps { label, steps, .. } => {
                        if let Some(g) = self.group_of(&label) {
                            self.record_steps(&g, &label, &steps, None)?;
                        }
                    }
                    ClientEvent::Events { label, events, .. } => self.log_events(None, label, events, None, &mut out)?,
                    ClientEvent::PeerError(e) => self.diag(format!("bundle: {e}")),
                    _ => {}
                }
            }
        }
        self.state.flush(&mut self.engine)?;
        Ok(out)
    }
}
