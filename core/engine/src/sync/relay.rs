//! Relay-only commits for sync (spec/sync-compaction.md §2 Relay-only commits): this node's own
//! ephemeral signal writes sealed per read sync ID, and a received relay-only blob opened and
//! delivered. Nothing of either is held.

use super::ThingSync;
use crate::error::Result;
use crate::labeling::Body;
use crate::Engine;
use osis_base::{BlobId, SyncId};
use osis_crypto::NodeRng;
use super::Wrap;
use std::collections::BTreeSet;

/// An own relay-only commit sealed for one sync ID: the blob ID, the blob and its wrap there.
#[derive(Clone, Debug)]
pub struct Relay {
    pub sync_id: SyncId,
    pub blob: BlobId,
    pub bytes: Vec<u8>,
    pub wrap: Wrap,
}

/// What opening a received relay-only blob did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayOpened {
    /// Verified and new here: its valid signal parts told to listeners; passed on.
    New,
    /// Delivered before, outside its window, or its author not held: dropped.
    Old,
    /// No held read secret opens it.
    NotOpen,
    /// It opened and is bad.
    Bad,
}

impl Engine {
    /// This node's relay-only commits not sent yet (`fire`), each sealed under every read sync
    /// ID whose closure holds a thing it writes (spec/sync-compaction.md §2: one a node sends
    /// goes to every peer sharing S), wrapped as `wrap_secret` says for its parts. One no read
    /// sync ID carries goes nowhere.
    pub fn take_relays(&mut self, rng: &mut dyn NodeRng) -> Result<Vec<Relay>> {
        let mut out = Vec::new();
        for c in self.take_signals() {
            let h = &c.blob.header;
            let mut things = BTreeSet::new();
            for a in &h.aspects {
                things.insert(a.tid);
                things.extend(self.enclosing(&a.tid));
            }
            for g in things {
                let ThingSync::Read(ids) = self.thing_sync_now(&g)? else { continue };
                let ctx = self.body_ctx(&g);
                let parts: Vec<usize> = c.blob.parts.iter().map(|p| p.ai).filter(|ai| h.aspects.get(*ai).is_some_and(|a| ctx.closure.contains(&a.tid))).collect();
                if parts.is_empty() {
                    continue;
                }
                let b = Body { commit: c.id, parts: parts.clone(), expires: osis_commit::blob_expiry(h), blind: h.blind, plaintext: c.blob.encode(), role_commit: false, order: 0, to_label: false };
                let Some(sealed) = self.seal(&b, osis_label::Class::Relay, &[], rng)? else { continue };
                let Some(w) = self.wrap_secret(&g, Some((&c.id, &parts)))? else { continue };
                let wrap = osis_crypto::wrap(&w, &sealed.id, &sealed.key, 0)?;
                for s in ids {
                    out.push(Relay { sync_id: s, blob: sealed.id, bytes: sealed.blob.clone(), wrap });
                }
            }
        }
        Ok(out)
    }

    /// A relay-only blob received under read S (spec/sync-compaction.md §2 Delivery): opened by
    /// its wrap with a held read secret, verified like an ephemeral commit, its valid signal
    /// parts told to listeners once; nothing of it kept.
    pub fn open_relay(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8]) -> Result<RelayOpened> {
        if osis_label::blob_id(bytes) != *blob {
            return Ok(RelayOpened::Bad);
        }
        let Some(t) = self.read_thing(s)? else { return Ok(RelayOpened::NotOpen) };
        let Some((_, key)) = osis_label::unwrap_any(self.read_secrets(&t).iter(), blob, wrap) else { return Ok(RelayOpened::NotOpen) };
        let opened = match self.open_commit(bytes, &key) {
            Ok(o) => o,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => return Ok(RelayOpened::Bad),
        };
        if opened.commit.header.ephemeral != Some(osis_commit::EphClass::Relay) {
            return Ok(RelayOpened::Bad);
        }
        match self.ingest_relay_blob(opened.commit) {
            Ok(true) => Ok(RelayOpened::New),
            Ok(false) => Ok(RelayOpened::Old),
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => Err(e),
            Err(_) => Ok(RelayOpened::Bad),
        }
    }
}
