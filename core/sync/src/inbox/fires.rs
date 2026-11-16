//! Sealed fires out (spec/sync-inbox.md §2 Delivery, §3 Sending).
//!
//! The engine owes each sealed fire durably until a peer takes it (`Engine::fires_owed`, then
//! `fires_feed` for each added). Per fire one `Effects` key follows the read epoch it seals to
//! (`Engine::fire_epoch`): sealed now (`Engine::sealed_fire`) and offered as a Deposit item held
//! outside the store (`Offers::add_fire`), sealed again as soon as that epoch moves (the
//! thing's public keys changed before a peer took it). Taken (answer 0), it ends
//! (`Engine::fire_taken`). A start seals each again: a sealed blob is kept in memory only.

use super::Here;
use super::offers::{Offers, Target};
use crate::types::Result;
use osis_base::memo::{Effects, Feed};
use osis_base::{BlobId, SyncId};
use osis_crypto::Epoch;
use osis_engine::sync::FireId;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct Fires {
    feed: Option<Feed<FireId>>,
    epochs: Effects<FireId, Option<Epoch>>,
    sent: BTreeMap<FireId, (SyncId, BlobId)>,
    by_blob: BTreeMap<(SyncId, BlobId), FireId>,
}

impl Default for Fires {
    fn default() -> Self {
        Fires { feed: None, epochs: Effects::new("inbox: fire epochs"), sent: BTreeMap::new(), by_blob: BTreeMap::new() }
    }
}

impl Fires {
    pub(super) fn start(&mut self, h: &mut Here<'_>) {
        self.feed = Some(h.engine.fires_feed());
        for id in h.engine.fires_owed() {
            self.epochs.want(id);
        }
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, offers: &mut Offers) -> Result<bool> {
        let mut acted = false;
        for (s, b) in offers.taken() {
            if let Some(id) = self.by_blob.remove(&(s, b)) {
                self.sent.remove(&id);
                self.epochs.unwant(&id);
                h.engine.fire_taken(&id)?;
                acted = true;
            }
        }
        if let Some(f) = self.feed.as_mut() {
            for id in f.added() {
                self.epochs.want(id);
            }
        }
        for id in self.epochs.due() {
            let engine = &mut *h.engine;
            let Some((_, now)) = self.epochs.try_settle(&id, || engine.fire_epoch(&id))? else { continue };
            acted = true;
            if let Some(k) = self.sent.remove(&id) {
                self.by_blob.remove(&k);
                offers.remove(&k.0, &k.1);
            }
            if now.is_none() {
                continue;
            }
            let Some(out) = h.engine.sealed_fire(&id)? else { continue };
            let b = osis_blob::blob_id(&out.blob);
            osis_base::costs::count("inbox: fire sealed", 1);
            let wrap = osis_crypto::filler_wrap(&mut osis_crypto::SeededRng::from_seed(osis_base::hash::hash(&out.blob)));
            offers.add_fire(out.sync_id, b, Arc::new(out.blob), wrap, Target::Fire { thing: out.thing, to: out.to });
            self.sent.insert(id, (out.sync_id, b));
            self.by_blob.insert((out.sync_id, b), id);
        }
        Ok(acted)
    }
}
