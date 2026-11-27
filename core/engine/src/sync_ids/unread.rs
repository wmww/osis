//! What a node keeping a thing unread holds of it (spec/sync.md §3 Kept unread, Kept for T): its
//! sync secrets and the sync ID it keeps for it, and nothing else (no roster, chain, `keys.0` or
//! commit). The sync ID a stub's sync-only cut gives (spec/wire.md §4 `SyncOnlyCut`,
//! spec/permissions.md §4 Stub) is one the thing is followed by; a cut is read for that sync ID
//! alone, nothing of it applies.
//!
//! Invariant (security; spec/sync.md §3 "only a step on the node's own path bearing the sync key
//! of a held secret keeps S's entries"): a sync-only cut is anyone's word who may log under a
//! sync ID (a writer, or a depositor); it names a sync ID to follow and gives no secret, step or
//! role. A cut naming a sync ID another thing owns here gives nothing (`actors::followed`).

use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, Role, SyncId, Tid};
use osis_commit::SyncOnlyCut;
use osis_crypto::{Epoch, Secret32};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `su/` + blob ID: a sync-only cut taken here: the thing it came under (15 bytes), then its
/// `SyncOnlyCut` bytes.
/// Invariant (bounds; spec/sync-ids.md §5 Peer budget): a row lives exactly as long as the store
/// holds an entry of its blob (`Engine::unnamed_cut`), and that entry is charged to its bringer
/// unless stamped (`Opened::SyncOnlyCut`), so what a party makes this node keep is bounded by its
/// budget, a writer's stamp aside.
pub(crate) const SYNC_CUTS: &[u8] = b"su/";

/// `se/` + thing (15 bytes) + holder (15 bytes): a holder's entry gave this node a sync secret of
/// the thing (`Core::took_sync_entry`); its value the sync ID. Kept until the thing is forgotten:
/// the secret it tells of is never taken back (spec/permissions.md §3 Lost access: a sync secret
/// held by no grant held is judged by its steps alone).
pub(crate) const ENTRY_SYNCS: &[u8] = b"se/";

/// What two blobs of one sync-only cut share: the hash of its canonical plaintext.
pub type ContentKey = [u8; 32];

/// The content key of a sync-only cut.
pub fn content_key(cut: &SyncOnlyCut) -> ContentKey {
    osis_base::hash::hash(&[b"osis sync-only cut".as_slice(), &cut.encode()].concat())
}

/// The sync-only cuts a sync ID carries, by content: the thing reading it each is under, and the
/// cut (`Engine::sync_cuts_carried`).
pub type Carried = BTreeMap<ContentKey, (Tid, SyncOnlyCut)>;

/// A sync-only cut taken here: the thing it came under and the cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldCut {
    pub under: Tid,
    pub cut: SyncOnlyCut,
}

/// Reads sync-only cut `plain`, come under `under`: `None` when it is bad input (not a cut; a cut
/// of `under` itself).
pub(crate) fn parse(under: Tid, plain: &[u8]) -> Option<HeldCut> {
    let cut = SyncOnlyCut::decode(plain).ok().filter(|c| c.thing != under)?;
    Some(HeldCut { under, cut })
}

/// Loads the sync-only cuts taken (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("sync-only cut row");
    let rows = tx.scan_rows(SYNC_CUTS, |k, v| {
        let b = BlobId(k.try_into().map_err(|_| bad())?);
        let (u, rest) = v.split_at_checked(15).ok_or_else(bad)?;
        Ok((b, parse(Tid::from_bytes(u.try_into().map_err(|_| bad())?), rest).ok_or_else(bad)?))
    })?;
    for (b, c) in rows {
        index(tx, b, c);
    }
    let bad = || Error::Corrupt("entry sync row");
    let rows = tx.scan_rows(ENTRY_SYNCS, |k, v| {
        let (t, u) = k.split_at_checked(15).ok_or_else(bad)?;
        let tid = |x: &[u8]| x.try_into().map(Tid::from_bytes).map_err(|_| bad());
        Ok((tid(t)?, tid(u)?, SyncId(v.try_into().map_err(|_| bad())?)))
    })?;
    for (t, u, s) in rows {
        index_entry(tx, t, u, s);
    }
    Ok(())
}

fn index_entry(tx: &mut Tx<'_>, thing: Tid, under: Tid, s: SyncId) {
    tx.core.ix.entry_syncs.insert(thing, (under, s));
    tx.core.ix.sync_cut_ids.insert(thing, s);
    tx.core.ix.sync_cut_things.insert(s, thing);
}

/// Notes that `under`'s entry under `s` gave this node a sync secret of `thing`.
pub(crate) fn note_entry(tx: &mut Tx<'_>, thing: Tid, under: Tid, s: SyncId) -> Result<()> {
    if tx.core.ix.entry_syncs.get(&thing).is_some_and(|x| x.contains(&(under, s))) {
        return Ok(());
    }
    tx.txn.put_local(&[ENTRY_SYNCS, thing.as_bytes().as_slice(), under.as_bytes()].concat(), &s.0, Shred::No)?;
    index_entry(tx, thing, under, s);
    Ok(())
}

fn index(tx: &mut Tx<'_>, b: BlobId, c: HeldCut) {
    tx.core.ix.sync_cuts.insert(b, c);
    tx.core.ix.sync_cuts_under.insert(c.under, b);
    tx.core.ix.sync_cut_ids.insert(c.cut.thing, c.cut.sync_id);
    tx.core.ix.sync_cut_things.insert(c.cut.sync_id, c.cut.thing);
}

/// Takes cut `c`, blob `b` (one taken already changes nothing).
pub(crate) fn note(tx: &mut Tx<'_>, b: &BlobId, c: HeldCut) -> Result<()> {
    if tx.core.ix.sync_cuts.contains_key(b) {
        return Ok(());
    }
    let v = [c.under.as_bytes().as_slice(), &c.cut.encode()].concat();
    tx.txn.put_local(&[SYNC_CUTS, &b.0].concat(), &v, Shred::No)?;
    index(tx, *b, c);
    Ok(())
}

/// Cut blob `b`'s row goes (the store holds no entry of it).
pub(crate) fn drop_blob(tx: &mut Tx<'_>, b: &BlobId) -> Result<()> {
    let Some(c) = tx.core.ix.sync_cuts.get(b).copied() else { return Ok(()) };
    tx.txn.remove_local(&[SYNC_CUTS, &b.0].concat(), Shred::No)?;
    tx.core.ix.sync_cuts.remove(b);
    tx.core.ix.sync_cuts_under.remove(&c.under, b);
    let left = tx.core.ix.sync_cuts.values().any(|x| x.cut == c.cut) || tx.core.ix.entry_syncs.get(&c.cut.thing).is_some_and(|x| x.iter().any(|(_, s)| *s == c.cut.sync_id));
    if !left {
        tx.core.ix.sync_cut_ids.remove(&c.cut.thing, &c.cut.sync_id);
        tx.core.ix.sync_cut_things.remove(&c.cut.sync_id, &c.cut.thing);
    }
    Ok(())
}

/// The sync-only cuts of `t` go (it is forgotten whole).
pub(crate) fn forget(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let blobs: Vec<(BlobId, HeldCut)> = tx.core.ix.sync_cuts.iter().filter(|(_, c)| c.cut.thing == *t).map(|(b, c)| (*b, *c)).collect();
    for (b, c) in blobs {
        tx.txn.remove_local(&[SYNC_CUTS, &b.0].concat(), Shred::No)?;
        tx.core.ix.sync_cuts.remove(&b);
        tx.core.ix.sync_cuts_under.remove(&c.under, &b);
    }
    let entries: Vec<(Tid, SyncId)> = tx.core.ix.entry_syncs.get(t).into_iter().flatten().copied().collect();
    for (u, _) in entries.iter() {
        tx.txn.remove_local(&[ENTRY_SYNCS, t.as_bytes().as_slice(), u.as_bytes()].concat(), Shred::No)?;
    }
    for e in entries {
        tx.core.ix.entry_syncs.remove(t, &e);
    }
    let ids: Vec<SyncId> = tx.core.ix.sync_cut_ids.get(t).into_iter().flatten().copied().collect();
    for s in ids {
        tx.core.ix.sync_cut_ids.remove(t, &s);
        tx.core.ix.sync_cut_things.remove(&s, t);
    }
    Ok(())
}

/// What this node keeps of thing `t` unread (spec/sync.md §3 Held sync secrets): the sync secrets
/// it holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unread {
    /// The secrets held that a step of the thing's `sync.0` state bears.
    pub secrets: BTreeMap<Epoch, Secret32>,
    /// Every sync secret held of the thing (`secrets` and those no such step bears yet): what is
    /// judged against the steps registered with this node (its stored path, osis-sync's;
    /// spec/crypto.md §4 Established: a step of its stored path bearing the secret's sync key).
    pub candidates: BTreeMap<Epoch, Secret32>,
}

impl Unread {
    pub(crate) fn holds_any(&self) -> bool {
        !self.secrets.is_empty()
    }
}

/// The sync key of sync secret `s` (spec/sync-ids.md §2).
pub(crate) fn sync_key(s: &Secret32) -> [u8; 32] {
    osis_crypto::role_key(osis_crypto::RoleKey::Sync, s).verifying_key().to_bytes()
}

impl Core {
    /// `t` as this node keeps it unread (`Unread`; `memo`: every sync ID judgement of it asks).
    pub(crate) fn unread(&self, t: &Tid) -> Arc<Unread> {
        self.unread_of.get(t, || Arc::new(self.unread_derived(t)))
    }

    fn unread_derived(&self, t: &Tid) -> Unread {
        // what role commits gave (a box applied, a lowering) and entries gave (a sync holder's,
        // spec/sync-ids.md §3 Taking an entry): `t`'s own sync secrets, never derived ones
        let candidates: BTreeMap<Epoch, Secret32> = self.ix.secrets.get(t).map(|e| e.role(Role::Sync).held().map(|(e, s)| (e, s.secret().clone())).collect()).unwrap_or_default();
        // borne by a step of its `sync.0`, or of the path heard of a sync ID it is followed by or its
        // `keys.0` names (spec/sync-ids.md §4 Owner)
        let recorded = self.ix.steps.get(t);
        let followed: BTreeSet<SyncId> = self.followed_links.get(t).map(|(ids, _)| ids).unwrap_or_default().into_iter().chain(self.cut_sync_ids(t)).chain(self.ix.keys_sync_id.get(t).copied()).collect();
        let heard: Vec<[u8; 32]> = followed.iter().filter_map(|s| self.heard.get(s)).flat_map(|p| p.iter().map(|st| st.keys.sync.to_bytes()).collect::<Vec<_>>()).collect();
        let bears = |k: &[u8; 32]| recorded.as_ref().is_some_and(|r| r.bears_sync(k)) || heard.contains(k);
        let secrets = candidates.iter().filter(|(_, s)| bears(&sync_key(s))).map(|(e, s)| (*e, s.clone())).collect();
        Unread { secrets, candidates }
    }

    /// Whether a sync-only cut of `x` was taken under `u` (spec/permissions.md §4 Stub: `u`'s unit
    /// holds only sync on `x`, as a reader of `u` holding `x`'s role entries logged it).
    pub(crate) fn cut_under(&self, u: &Tid, x: &Tid) -> bool {
        self.ix.sync_cuts_under.get(u).into_iter().flatten().any(|b| self.ix.sync_cuts.get(b).is_some_and(|c| c.cut.thing == *x)) || self.ix.entry_syncs.get(x).is_some_and(|e| e.iter().any(|(h, _)| h == u))
    }

    /// The sync IDs the sync-only cuts taken here give `t` (`SYNC_CUTS`).
    pub(crate) fn cut_sync_ids(&self, t: &Tid) -> BTreeSet<SyncId> {
        self.ix.sync_cut_ids.get(t).into_iter().flatten().copied().collect()
    }
}

impl crate::engine::Engine {
    /// Takes sync-only cut `plain`, blob `b`, come under `under` (`parse`; `note`): `false` when
    /// it is bad input.
    pub(crate) fn take_sync_cut(&mut self, under: &Tid, b: &BlobId, plain: &[u8]) -> Result<bool> {
        let Some(c) = parse(*under, plain) else { return Ok(false) };
        let b = *b;
        self.run(|tx| note(tx, &b, c))?;
        Ok(true)
    }

    /// A sync holder's entry under `s` gave this node a sync secret of `thing` (spec/sync-ids.md
    /// §3 Taking an entry): holder `under` holds sync on `thing`, as a sync-only cut of `thing`
    /// under `under` says (spec/sync-set.md §2 Holding a stub: a sync holder's stub is the
    /// sync-only cut and what its entries give it). The public's entry and a link key's name no
    /// holder.
    pub(crate) fn took_sync_entry(&mut self, s: &SyncId, thing: Tid, under: Option<Tid>) -> Result<()> {
        let Some(under) = under.filter(|u| !u.is_public() && *u != thing) else { return Ok(()) };
        let s = *s;
        self.run(|tx| note_entry(tx, thing, under, s))
    }

    /// No store entry names blob `b` any more: its sync-only cut row (`SYNC_CUTS`), if any, goes.
    pub fn unnamed_cut(&mut self, b: &BlobId) -> Result<()> {
        if !self.core.ix.sync_cuts.contains_key(b) {
            return Ok(());
        }
        let b = *b;
        self.run(|tx| drop_blob(tx, &b))
    }

    /// The blobs of every sync-only cut row (a start drops those the store does not hold).
    pub fn cut_blobs(&self) -> Vec<BlobId> {
        self.core.ix.sync_cuts.keys().copied().collect()
    }

    /// The sync-only cuts read sync ID `s` carries (spec/permissions.md §4 Stub, Logging
    /// certificates), by content, each with the thing reading `s` it is under: per stub its
    /// read things' certificates carry as sync-only (`Certs::sync_cuts`), the stub's thing and
    /// the sync ID this node holds for it, and each cut taken under one of them whose stub they
    /// carry so.
    pub fn sync_cuts_carried(&mut self, s: &SyncId) -> Result<Arc<Carried>> {
        self.follow_certificates()?;
        let mut out = BTreeMap::new();
        for t in self.read_things_of(s)? {
            let stubs: Vec<Tid> = self.core.certified.sync_cuts.get(&t).into_iter().flat_map(|x| x.iter().copied()).collect();
            for x in &stubs {
                for o in self.sync_ids(x)?.iter().filter(|o| !o.hint) {
                    let cut = SyncOnlyCut { thing: *x, sync_id: o.id };
                    out.insert(content_key(&cut), (t, cut));
                }
            }
            let blobs: Vec<BlobId> = self.core.ix.sync_cuts_under.get(&t).into_iter().flatten().copied().collect();
            for b in blobs {
                let Some(c) = self.core.ix.sync_cuts.get(&b).copied() else { continue };
                if stubs.contains(&c.cut.thing) {
                    out.entry(content_key(&c.cut)).or_insert((t, c.cut));
                }
            }
        }
        Ok(Arc::new(out))
    }

    /// The sync-only cut rows taken under the things reading `s`: per blob, its content.
    pub fn sync_cut_rows(&mut self, s: &SyncId) -> BTreeMap<BlobId, ContentKey> {
        let mut out = BTreeMap::new();
        for t in self.read_things_of(s).unwrap_or_default() {
            for b in self.core.ix.sync_cuts_under.get(&t).into_iter().flatten() {
                if let Some(c) = self.core.ix.sync_cuts.get(b) {
                    out.insert(*b, content_key(&c.cut));
                }
            }
        }
        out
    }

    /// A fresh blob under `s` of the sync-only cut of content `key` it carries
    /// (`sync_cuts_carried`), framed as a record blob is (spec/wire.md §3, §4: committing to a
    /// writer delete key of the thing it is under), its row taken as this node's: `None` where
    /// `s` carries none such or nothing may be wrapped for it now.
    pub fn seal_sync_cut(&mut self, s: &SyncId, key: &ContentKey, rng: &mut dyn osis_crypto::NodeRng) -> Result<Option<(BlobId, Vec<u8>, crate::sync::Wrap)>> {
        let carried = self.sync_cuts_carried(s)?;
        let Some((t, cut)) = carried.get(key).copied() else { return Ok(None) };
        let Some(w) = self.wrap_secret(&t, None)? else { return Ok(None) };
        let Some(dk) = self.read(|tx| crate::engine::secrets::writer_delete_key_in(tx, &t))? else { return Ok(None) };
        let (id, blob, wrap, _) = crate::sync::certblobs::seal_cert_blob(&w, &dk, &cut.encode(), BTreeSet::new(), rng)?;
        let c = HeldCut { under: t, cut };
        self.run(|tx| note(tx, &id, c))?;
        Ok(Some((id, blob, wrap)))
    }
}
