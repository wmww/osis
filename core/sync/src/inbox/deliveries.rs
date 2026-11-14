//! The inbox blobs this node owes (spec/sync-inbox.md §2 Logging, Re-send).
//!
//! The engine lists the deliveries owed (`deliveries` at a start, then `delivery_feed` for each
//! added); this module follows each delivery through its own `Effects` key: where it goes (the
//! recipient's inbox now, `inbox_of`) and whether it was seen taken (the engine's commit sign,
//! `delivery_taken`, or an open of a sync ID its blob names on a connection where the recipient
//! is proven, which only sync sees: `opened`). Seen taken, it ends: `Engine::delivered` drops the
//! engine's row. A delivery due goes out as one blob, sealed now and logged under the inbox:
//! stamped where this node writes the inbox, else deposited and offered as a Deposit item. It is
//! sealed again at that blob's prefix expiry (a timer per delivery) and as soon as the inbox
//! moved, never by walking what was sent.
//!
//! Durable: per delivery the blob sent (sync ID, blob, expiry) (store rows `I/d/`), so a restart
//! does not seal again. A row goes when its delivery ends or the engine owes it no more.

use super::offers::{Offers, Target};
use super::{Here, Net, own_entry};
use crate::types::{ConnId, Credential, Result};
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::memo::{Effects, Feed, Stamped};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_engine::Engine;
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
}

impl Sent {
    fn encode(&self) -> Vec<u8> {
        [&self.s.0[..], &self.blob.0, &self.expires.0.to_be_bytes()].concat()
    }
    fn decode(v: &[u8]) -> Option<Sent> {
        let s = SyncId(v.get(..16)?.try_into().ok()?);
        let blob = BlobId(v.get(16..48)?.try_into().ok()?);
        let expires = WallMs(u64::from_be_bytes(v.get(48..56)?.try_into().ok()?));
        Some(Sent { s, blob, expires })
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
    /// The engine's deliveries added since the last settle.
    feed: Option<Feed<Key>>,
    names: BTreeMap<Key, Arc<Vec<SyncId>>>,
    by_name: BTreeMap<SyncId, BTreeSet<Key>>,
    judged: Effects<Key, Want>,
    wants: BTreeMap<Key, Want>,
    sent: BTreeMap<Key, Sent>,
    /// The opens seen of a sync ID its blob names with the recipient proven, each by its
    /// credential's read epoch (`None`: a store credential): read by `judge`, so stamped.
    seen: Stamped<Key, BTreeSet<(SyncId, Option<osis_crypto::Epoch>)>>,
    /// Each blob sent by its expiry: sealed again then.
    resend: BTreeSet<(WallMs, Key)>,
}

impl Default for Deliveries {
    fn default() -> Self {
        Deliveries { feed: None, names: BTreeMap::new(), by_name: BTreeMap::new(), judged: Effects::new("inbox: delivery"), wants: BTreeMap::new(), sent: BTreeMap::new(), seen: Stamped::default(), resend: BTreeSet::new() }
    }
}

impl Deliveries {
    /// Loads what was sent before this start and follows every delivery owed; a deposited blob
    /// is offered again; rows of deliveries no longer owed go.
    pub(super) fn start(&mut self, h: &mut Here<'_>, offers: &mut Offers) -> Result<()> {
        self.feed = Some(h.engine.delivery_feed());
        let owed = h.engine.deliveries()?;
        let rows = h.store.with_tx(|t| t.scan_local(ROWS, b"", usize::MAX))?;
        for (row, v) in rows {
            let (Some(k), Some(sent)) = (key_of(&row), Sent::decode(&v)) else { continue };
            if !owed.contains(&k) {
                h.store.with_tx(|t| t.remove_local(&row, Shred::No))?;
                continue;
            }
            if h.store.entry(&sent.s, &sent.blob)?.is_some_and(|e| e.deposited && e.own) {
                offers.add(sent.s, sent.blob, Target::Recipient(k.1));
            }
            self.resend.insert((sent.expires, k));
            self.sent.insert(k, sent);
        }
        for k in owed.iter() {
            self.follow(h, *k)?;
        }
        Ok(())
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, offers: &mut Offers) -> Result<bool> {
        let mut acted = false;
        let added = self.feed.as_mut().map(|f| f.added()).unwrap_or_default();
        for k in added {
            if !self.names.contains_key(&k) {
                self.follow(h, k)?;
                acted = true;
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
            let (engine, seen) = (&mut *h.engine, &self.seen);
            let Some((_, now)) = self.judged.try_settle(&k, || judge(engine, seen, &k))? else { continue };
            acted = true;
            match now {
                Want::Taken => {
                    // seen taken (or no longer owed): the delivery ends, here and in the engine
                    h.engine.delivered(&k.0, &k.1)?;
                    self.forget(h, offers, &k)?;
                }
                Want::To(s) => {
                    self.wants.insert(k, Want::To(s));
                    let live = self.sent.get(&k).is_some_and(|x| x.s == s && x.expires > h.now);
                    if !live {
                        self.send(h, offers, k, s)?;
                    }
                    if self.sent.get(&k).is_some_and(|x| x.s == s) && took_own(h.engine, &s)? {
                        h.engine.delivered(&k.0, &k.1)?;
                        self.forget(h, offers, &k)?;
                    }
                }
                Want::Unreachable => {
                    self.wants.insert(k, Want::Unreachable);
                }
            }
        }
        Ok(acted)
    }

    /// A delivery owed: followed.
    fn follow(&mut self, h: &mut Here<'_>, k: Key) -> Result<()> {
        let names = h.engine.delivery_names(&k.0, &k.1)?;
        for s in names.iter() {
            self.by_name.entry(*s).or_default().insert(k);
        }
        self.names.insert(k, names);
        self.judged.want(k);
        osis_base::costs::count("inbox: deliveries followed", 1);
        Ok(())
    }

    fn forget(&mut self, h: &mut Here<'_>, offers: &mut Offers, k: &Key) -> Result<()> {
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
        if self.seen.contains_key(k) {
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
    fn send(&mut self, h: &mut Here<'_>, offers: &mut Offers, k: Key, s: SyncId) -> Result<()> {
        let (c, holder) = k;
        let Some(bytes) = h.engine.inbox_blob(&c, &holder, &mut *h.rng)? else { return Ok(()) };
        osis_base::costs::count("inbox: sealed", 1);
        let b = osis_label::blob_id(&bytes);
        let expires = osis_label::Prefix::parse(&bytes).ok().and_then(|p| p.expiry()).unwrap_or(WallMs(h.now.0.saturating_add(INBOX_LIFETIME_MS)));
        let keys = h.engine.signers(&s, Some(&holder))?;
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
        let sent = Sent { s, blob: b, expires };
        h.store.with_tx(|t| t.put_local(&row_key(&k), &sent.encode(), Shred::No))?;
        self.sent.insert(k, sent);
        self.resend.insert((expires, k));
        Ok(())
    }

    /// S joined a connection's shared set: a delivery naming S whose recipient is proven there
    /// is judged again on the credential that opened it (`judge`, spec/sync-inbox.md §2 Re-send).
    pub(super) fn opened(&mut self, conn: ConnId, s: &SyncId, net: &impl Net) {
        let Some(ks) = self.by_name.get(s) else { return };
        let by = match net.member(conn, s).map(|m| m.by) {
            Some(Credential::ReadSecret(e)) => Some(e),
            Some(Credential::SyncKey | Credential::SyncProof | Credential::Claim) => None,
            // J and static entries show nothing the delivery gave
            _ => return,
        };
        let actors = net.actors(conn);
        for k in ks.clone() {
            if !actors.contains(&k.1) {
                continue;
            }
            let mut v = self.seen.get(&k).cloned().unwrap_or_default();
            if v.insert((*s, by)) {
                self.seen.insert(k, v);
            }
        }
    }

    pub(super) fn next_wake(&self) -> Option<WallMs> {
        self.resend.first().map(|(t, _)| *t)
    }

}

fn judge(engine: &mut Engine, seen: &Stamped<Key, BTreeSet<(SyncId, Option<osis_crypto::Epoch>)>>, k: &Key) -> Result<Want> {
    osis_base::costs::count("inbox: delivery judged", 1);
    if engine.delivery_taken(&k.0, &k.1)? || opened_taken(engine, &k.1, seen.get(k))? {
        return Ok(Want::Taken);
    }
    Ok(match engine.inbox_of(&k.1) {
        Some(s) => Want::To(s),
        None => Want::Unreachable,
    })
}

/// spec/sync-inbox.md §2 Re-send (the sender reads the inbox): a blob logged here under an inbox
/// this node reads is taken here (this node holds its commit), so the delivery ends once sent;
/// the inbox's other readers get the logged blob by syncing the inbox.
fn took_own(engine: &mut Engine, s: &SyncId) -> Result<bool> {
    Ok(matches!(engine.sync_holding(s)?, Some((_, osis_engine::sync::Holding::Read))))
}

/// spec/sync-inbox.md §2 Re-send: an open of a sync ID the blob names, the recipient proven,
/// shows the delivery taken only by a credential the delivery's secrets give: to a recipient
/// reading S's thing here, a read secret at a current epoch of it (an older one opened before the
/// grant was taken: a grant again after a removal, or a sync holder raised to read); to a holder
/// of sync alone, a store credential (its head's).
fn opened_taken(engine: &mut Engine, holder: &osis_base::Tid, seen: Option<&BTreeSet<(SyncId, Option<osis_crypto::Epoch>)>>) -> Result<bool> {
    for (s, by) in seen.into_iter().flatten() {
        match by {
            None => {
                if engine.judge_peer(s, std::slice::from_ref(holder))? == osis_engine::sync::J::SyncHolder {
                    return Ok(true);
                }
            }
            Some(e) => {
                if engine.read_credentials(s)?.is_some_and(|c| c.read_secrets.iter().any(|(x, _)| x == e)) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
