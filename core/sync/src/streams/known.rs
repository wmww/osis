//! What each source's stream showed (spec/sync-judgement.md §3 `known`), with what else a source
//! told on its stream: its head per sync ID, full, and the refusals it sent (spec/sync-streams.md
//! §4 Full, Refused). Every read and write is stamped, so a memo or `Effects` reading it is moved
//! by exactly the source, sync ID and entry that changed.
//!
//! A source is a peer's record, or the connection for a peer with none (`store::Source`).
//! Ephemeral entries are known only through the connection that listed them (they have no log
//! position and are lost at a restart without an event), so they are kept under
//! `Source::Conn` and go with it.

use crate::store::Source;
use osis_base::memo::Stamps;
use osis_base::{BlobId, SyncId};
use osis_label::StepId;
use osis_proto::{Code, Stamp};
use std::collections::{BTreeMap, BTreeSet};

/// A refusal a source sent for one entry, and the ground it holds on: the entry's stamp and the
/// source's head when it arrived (spec/sync-streams.md §4 Refused).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: Code,
    pub stamp: Option<Stamp>,
    pub head: Option<StepId>,
}

#[derive(Clone, Debug, Default)]
pub struct Known {
    by_src: BTreeMap<(Source, SyncId), BTreeSet<BlobId>>,
    by_blob: BTreeMap<(SyncId, BlobId), BTreeSet<Source>>,
    heads: BTreeMap<(Source, SyncId), StepId>,
    full: BTreeSet<(Source, SyncId)>,
    refused: BTreeMap<(Source, SyncId, BlobId), Refusal>,
    stamps: Stamps,
}

impl Known {
    fn wrote(&self, src: Source, s: &SyncId, b: &BlobId) {
        self.stamps.wrote(&("k", src, s, b), true);
        self.stamps.wrote(&("p", s, b), true);
        self.stamps.wrote(&("l", src, s), true);
    }

    /// `src` showed `b` present under S. Whether it was new.
    pub fn add(&mut self, src: Source, s: SyncId, b: BlobId) -> bool {
        let new = self.by_src.entry((src, s)).or_default().insert(b);
        if new {
            self.by_blob.entry((s, b)).or_default().insert(src);
            self.wrote(src, &s, &b);
        }
        new
    }

    /// `src` showed `b` gone under S (its deletion, or a refusal as tombstoned).
    pub fn remove(&mut self, src: Source, s: SyncId, b: &BlobId) -> bool {
        let Some(set) = self.by_src.get_mut(&(src, s)) else { return false };
        if !set.remove(b) {
            return false;
        }
        if set.is_empty() {
            self.by_src.remove(&(src, s));
        }
        if let Some(srcs) = self.by_blob.get_mut(&(s, *b)) {
            srcs.remove(&src);
            if srcs.is_empty() {
                self.by_blob.remove(&(s, *b));
            }
        }
        self.wrote(src, &s, b);
        true
    }

    /// Whether `src`'s stream showed `b` present under S.
    pub fn knows(&self, src: Source, s: &SyncId, b: &BlobId) -> bool {
        self.stamps.read(&("k", src, s, b));
        self.by_src.get(&(src, *s)).is_some_and(|x| x.contains(b))
    }

    /// Whether any source's stream showed `b` present under S.
    pub fn present(&self, s: &SyncId, b: &BlobId) -> bool {
        self.stamps.read(&("p", s, b));
        self.by_blob.contains_key(&(*s, *b))
    }

    /// What `src`'s stream showed present under S.
    pub fn list(&self, src: Source, s: &SyncId) -> Vec<BlobId> {
        self.stamps.read(&("l", src, s));
        self.by_src.get(&(src, *s)).map(|x| x.iter().copied().collect()).unwrap_or_default()
    }

    /// Everything `src` showed under S goes (S left the node, or a trimmed listing replaces it).
    pub fn forget(&mut self, src: Source, s: SyncId) {
        for b in self.list(src, &s) {
            self.remove(src, s, &b);
        }
        self.set_full(src, s, false);
        if self.heads.remove(&(src, s)).is_some() {
            self.stamps.wrote(&("h", src, s), false);
        }
        let gone: Vec<_> = self.refused.range((src, s, BlobId([0; 32]))..=(src, s, BlobId([0xff; 32]))).map(|(k, _)| *k).collect();
        for k in gone {
            self.refused.remove(&k);
            self.stamps.wrote(&("r", k), false);
        }
    }

    /// Everything a source showed (a connection that ended: its ephemeral entries and what a peer
    /// with no record showed).
    pub fn forget_source(&mut self, src: Source) {
        let ids: BTreeSet<SyncId> = self.by_src.range((src, SyncId([0; 16]))..=(src, SyncId([0xff; 16]))).map(|((_, s), _)| *s).chain(self.full.iter().filter(|(x, _)| *x == src).map(|(_, s)| *s)).chain(self.heads.keys().filter(|(x, _)| *x == src).map(|(_, s)| *s)).collect();
        for s in ids {
            self.forget(src, s);
        }
    }

    pub fn set_head(&mut self, src: Source, s: SyncId, head: StepId) {
        if self.heads.insert((src, s), head) != Some(head) {
            self.stamps.wrote(&("h", src, s), true);
        }
    }

    /// The source's step for S: the head its stream last named.
    pub fn head(&self, src: Source, s: &SyncId) -> Option<StepId> {
        self.stamps.read(&("h", src, s));
        self.heads.get(&(src, *s)).copied()
    }

    pub fn set_full(&mut self, src: Source, s: SyncId, full: bool) {
        let changed = if full { self.full.insert((src, s)) } else { self.full.remove(&(src, s)) };
        if changed {
            self.stamps.wrote(&("f", src, s), full);
        }
    }

    /// Whether the source told it is full for S.
    pub fn full(&self, src: Source, s: &SyncId) -> bool {
        self.stamps.read(&("f", src, s));
        self.full.contains(&(src, *s))
    }

    pub fn set_refused(&mut self, src: Source, s: SyncId, b: BlobId, r: Refusal) {
        self.stamps.wrote(&("r", (src, s, b)), true);
        self.refused.insert((src, s, b), r);
    }

    pub fn refusal(&self, src: Source, s: &SyncId, b: &BlobId) -> Option<&Refusal> {
        self.stamps.read(&("r", (src, *s, *b)));
        self.refused.get(&(src, *s, *b))
    }
}
