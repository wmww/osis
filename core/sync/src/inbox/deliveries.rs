//! The inbox blobs this node owes (spec/sync-inbox.md §2 Logging, Re-send).
//!
//! The engine lists the deliveries owed and not seen taken by a commit of the recipient's
//! (`Ground::deliveries`); this module follows that list through one `Effects` key and each
//! delivery through its own: where it goes (the recipient's inbox now, `inbox_of`) and whether
//! it was seen taken (the engine's commit sign, or an open of a sync ID its blob names on a
//! connection where the recipient is proven, which only sync sees: `opened`). A delivery due goes
//! out as one blob, sealed now and logged under the inbox: stamped where this node writes the
//! inbox, else deposited and offered as a Deposit item. It is sealed again at that blob's prefix
//! expiry (a timer per delivery) and as soon as the inbox moved, never by walking what was sent.
//!
//! Durable: per delivery the blob sent (sync ID, blob, expiry) and whether the recipient was seen
//! opening what it names (store rows `I/d/`), so a restart neither seals again nor forgets an
//! open seen. A row goes when the engine lists the delivery no more.

use super::offers::{Offers, Target};
use super::{Ground, Here, Net, own_entry, settled};
use crate::types::{ConnId, Result};
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::memo::{Effects, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_proto::Code;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Key = (CommitId, Tid);

const ROWS: &[u8] = b"I/d/";

/// The blob a delivery last went out as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sent {
    pub s: SyncId,
    pub blob: BlobId,
    pub expires: WallMs,
    /// The recipient was seen opening a sync ID the blob names.
    pub seen: bool,
}

impl Sent {
    fn encode(&self) -> Vec<u8> {
        [&self.s.0[..], &self.blob.0, &self.expires.0.to_be_bytes(), &[u8::from(self.seen)]].concat()
    }
    fn decode(v: &[u8]) -> Option<Sent> {
        let s = SyncId(v.get(..16)?.try_into().ok()?);
        let blob = BlobId(v.get(16..48)?.try_into().ok()?);
        let expires = WallMs(u64::from_be_bytes(v.get(48..56)?.try_into().ok()?));
        Some(Sent { s, blob, expires, seen: *v.get(56)? != 0 })
    }
}

fn row_key(k: &Key) -> Vec<u8> {
    [ROWS, &k.0.0, k.1.as_bytes()].concat()
}

fn key_of(row: &[u8]) -> Option<Key> {
    let c = CommitId(row.get(ROWS.len()..ROWS.len() + 32)?.try_into().ok()?);
    let t = Tid::from_bytes(row.get(ROWS.len() + 32..)?.try_into().ok()?);
    Some((c, t))
}

/// Where a delivery goes now.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Want {
    /// Seen taken: nothing more is sent.
    Taken,
    /// The recipient's `keys.0` names no inbox here: it cannot be reached.
    Unreachable,
    To(SyncId),
}

#[derive(Clone)]
pub(super) struct Deliveries {
    list: Effects<(), Arc<BTreeSet<Key>>>,
    names: BTreeMap<Key, Arc<Vec<SyncId>>>,
    by_name: BTreeMap<SyncId, BTreeSet<Key>>,
    judged: Effects<Key, Want>,
    wants: BTreeMap<Key, Want>,
    sent: BTreeMap<Key, Sent>,
    /// Seen opening a sync ID its blob names (read by `judge`, so stamped).
    seen: StampedSet<Key>,
    /// Seen since the last settle: their rows are written there.
    seen_new: BTreeSet<Key>,
    /// Each blob sent by its expiry: sealed again then.
    resend: BTreeSet<(WallMs, Key)>,
}

impl Default for Deliveries {
    fn default() -> Self {
        let mut list = Effects::new("inbox: deliveries");
        list.want(());
        Deliveries { list, names: BTreeMap::new(), by_name: BTreeMap::new(), judged: Effects::new("inbox: delivery"), wants: BTreeMap::new(), sent: BTreeMap::new(), seen: StampedSet::default(), seen_new: BTreeSet::new(), resend: BTreeSet::new() }
    }
}

impl Deliveries {
    /// Loads what was sent before this start; a deposited blob not seen taken is offered again.
    pub(super) fn start<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers) -> Result<()> {
        let rows = h.store.with_tx(|t| t.scan_local(ROWS, b"", usize::MAX))?;
        for (k, v) in rows {
            let (Some(k), Some(sent)) = (key_of(&k), Sent::decode(&v)) else { continue };
            if sent.seen {
                self.seen.insert(k);
            } else if h.store.entry(&sent.s, &sent.blob)?.is_some_and(|e| e.deposited && e.own) {
                offers.add(sent.s, sent.blob, Target::Recipient(k.1));
            }
            self.resend.insert((sent.expires, k));
            self.sent.insert(k, sent);
        }
        Ok(())
    }

    pub(super) fn settle<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers) -> Result<bool> {
        let mut acted = false;
        for k in std::mem::take(&mut self.seen_new) {
            if let Some(s) = self.sent.get_mut(&k) {
                s.seen = true;
                let row = s.encode();
                h.store.with_tx(|t| t.put_local(&row_key(&k), &row, Shred::No))?;
            }
        }
        if !self.list.due().is_empty() {
            let g = &mut *h.g;
            if let Some((_, now)) = settled(&mut self.list, &(), Arc::default(), || g.deliveries())? {
                acted |= self.follow(h, offers, &now)?;
            }
        }
        while let Some(&(t, k)) = self.resend.first() {
            if t > h.now {
                break;
            }
            self.resend.remove(&(t, k));
            if let Some(Want::To(s)) = self.wants.get(&k).cloned() {
                self.send(h, offers, k, s)?;
                acted = true;
            }
        }
        for k in self.judged.due() {
            let (g, seen) = (&mut *h.g, &self.seen);
            let Some((_, now)) = settled(&mut self.judged, &k, Want::Unreachable, || judge(g, seen, &k))? else { continue };
            acted = true;
            self.wants.insert(k, now.clone());
            match now {
                Want::Taken => {
                    if let Some(old) = self.sent.get(&k) {
                        offers.remove(&old.s, &old.blob);
                        self.resend.remove(&(old.expires, k));
                    }
                }
                Want::To(s) => {
                    let live = self.sent.get(&k).is_some_and(|x| x.s == s && x.expires > h.now);
                    if !live {
                        self.send(h, offers, k, s)?;
                    }
                }
                Want::Unreachable => {}
            }
        }
        Ok(acted)
    }

    /// The engine's list moved: deliveries newly owed are followed, those gone are forgotten.
    fn follow<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers, now: &BTreeSet<Key>) -> Result<bool> {
        let gone: Vec<Key> = self.names.keys().filter(|k| !now.contains(*k)).copied().collect();
        // rows of deliveries the list no longer names (taken, or the commit forgotten)
        let stale: Vec<Key> = self.sent.keys().filter(|k| !now.contains(*k) && !self.names.contains_key(*k)).copied().collect();
        let added: Vec<Key> = now.iter().filter(|k| !self.names.contains_key(*k)).copied().collect();
        let acted = !gone.is_empty() || !added.is_empty() || !stale.is_empty();
        for k in gone.into_iter().chain(stale) {
            self.forget(h, offers, &k)?;
        }
        for k in added {
            let names = h.g.delivery_names(&k.0, &k.1)?;
            for s in names.iter() {
                self.by_name.entry(*s).or_default().insert(k);
            }
            self.names.insert(k, names);
            self.judged.want(k);
        }
        osis_base::costs::count("inbox: deliveries followed", now.len() as u64);
        Ok(acted)
    }

    fn forget<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers, k: &Key) -> Result<()> {
        if let Some(names) = self.names.remove(k) {
            for s in names.iter() {
                if let Some(ks) = self.by_name.get_mut(s) {
                    ks.remove(k);
                    if ks.is_empty() {
                        self.by_name.remove(s);
                    }
                }
            }
        }
        self.judged.unwant(k);
        self.wants.remove(k);
        if self.seen.contains(k) {
            self.seen.remove(k);
        }
        if let Some(old) = self.sent.remove(k) {
            offers.remove(&old.s, &old.blob);
            self.resend.remove(&(old.expires, *k));
            h.store.with_tx(|t| t.remove_local(&row_key(k), Shred::No))?;
        }
        Ok(())
    }

    /// Seals delivery `k` now and logs it under inbox `s`: stamped where this node writes `s`,
    /// else deposited and offered. The blob it replaces is moot.
    fn send<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers, k: Key, s: SyncId) -> Result<()> {
        let (c, holder) = k;
        let Some(bytes) = h.g.inbox_blob(&c, &holder, &mut *h.rng)? else { return Ok(()) };
        osis_base::costs::count("inbox: sealed", 1);
        let b = osis_label::blob_id(&bytes);
        let expires = osis_label::Prefix::parse(&bytes).ok().and_then(|p| p.expiry()).unwrap_or(WallMs(h.now.0.saturating_add(INBOX_LIFETIME_MS)));
        let keys = h.g.signers(&s, Some(&holder))?;
        let wrap = osis_crypto::filler_wrap(&mut *h.rng);
        let deposited = match (&keys.stamp, &keys.deposit) {
            (Some(w), _) => {
                let stamp = osis_label::sign_stamp(w, &s, &b, &wrap, false);
                if h.store.log(&s, own_entry(b, wrap, Some(stamp), Some(expires)), Some(bytes), None)? != Code::OK {
                    return Ok(());
                }
                false
            }
            (None, Some(_)) => {
                if h.store.log(&s, own_entry(b, wrap, None, Some(expires)), Some(bytes), None)? != Code::OK {
                    return Ok(());
                }
                true
            }
            // no key to sign with: nothing here reaches the inbox
            (None, None) => return Ok(()),
        };
        if let Some(old) = self.sent.get(&k) {
            offers.remove(&old.s, &old.blob);
            self.resend.remove(&(old.expires, k));
        }
        if deposited {
            offers.add(s, b, Target::Recipient(holder));
        }
        let sent = Sent { s, blob: b, expires, seen: self.seen.contains(&k) };
        h.store.with_tx(|t| t.put_local(&row_key(&k), &sent.encode(), Shred::No))?;
        self.sent.insert(k, sent);
        self.resend.insert((expires, k));
        Ok(())
    }

    /// S joined a connection's shared set: a delivery naming S whose recipient is proven there
    /// was seen taken (spec/sync-inbox.md §2 Re-send).
    pub(super) fn opened(&mut self, conn: ConnId, s: &SyncId, net: &impl Net) {
        let Some(ks) = self.by_name.get(s) else { return };
        let actors = net.actors(conn);
        for k in ks {
            if actors.contains(&k.1) && !self.seen.contains(k) {
                self.seen.insert(*k);
                self.seen_new.insert(*k);
            }
        }
    }

    pub(super) fn next_wake(&self) -> Option<WallMs> {
        self.resend.first().map(|(t, _)| *t)
    }

}

fn judge<G: Ground>(g: &mut G, seen: &StampedSet<Key>, k: &Key) -> Result<Want> {
    osis_base::costs::count("inbox: delivery judged", 1);
    if seen.contains(k) || g.delivery_taken(&k.0, &k.1)? {
        return Ok(Want::Taken);
    }
    Ok(match g.inbox_of(&k.1)? {
        Some(s) => Want::To(s),
        None => Want::Unreachable,
    })
}
