//! Judgement for kept-unread sync IDs (spec/sync-judgement.md §6, spec/sync-set.md §3).
//!
//! Principle: a node keeping S unread decides its own grant by the boxes sealed to it and the
//! removal notices to it, nothing else. It holds no engine state of what S carries: its inputs
//! are the engine's sync records (sync secrets by epoch), sync set and removal notices, and the
//! store's path and own entries of S (`Ground`), and whether a source holds an own entry
//! (`Sources`). It keeps S while the sync set lists S kept unread; it is stranded (opens nothing,
//! keeps its store) while no held secret derives its head's sync key; it stops at once, shredding
//! S and dropping the record, on a removal notice whose signature verifies under the delete key of
//! a step of its path from the newest step whose sync secret it holds up to its head (judged again
//! at each head move while held); unlisted, it leaves once each entry it logged itself is present
//! at a source. Model: core/test/tla/net/NetKeep.tla.
//!
//! Work follows change: the three engine values are whole maps, read each through one `Effects`
//! key and projected, by a diff on change, into per-key stamped maps (`listed`, `records`,
//! `notices`); one `Effects` key per S reads those by key plus the store's path of S, so a head
//! move, a record or a notice judges only its own S. The diffs cost the map's size per change of
//! that map (a facade with per-key values would remove them).
//!
//! State: the projections and `kept` (per S: stranded, credentials), which `opens` and `status`
//! read stamped. Nothing durable of its own: a start settles every key once.

use crate::store::Store;
use crate::streams::Streams;
use crate::types::{Cx, Error, Result};
use osis_base::memo::{Effects, Stamped};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_crypto::{LabelRole, Secret32, SigningSecret, VerifyingKey, label_role_key, label_role_seed};
use osis_crypto::kdf::sync_proof;
use osis_engine::sync::{Holding, Path, RemovalNotice, SyncRecord, SyncSet};
use osis_label::{ClaimSet, verify_removal};
use std::collections::BTreeMap;
use std::sync::Arc;

/// What a node keeping S unread opens and acts with, from its sync record and its store's head
/// (spec/sync-opens.md §4: it shows its head's sync key, the sync proof of it, its deposit key and
/// the head's claim set).
#[derive(Clone, Debug)]
pub struct UnreadCredentials {
    /// The head's sync key.
    pub sync: SigningSecret,
    /// Its sync proof (spec/sync-ids.md §2).
    pub proof: Secret32,
    /// The head's deposit key (public: a node keeping S unread signs no deposit).
    pub deposit: VerifyingKey,
    /// The head's claim set.
    pub claims: Option<ClaimSet>,
}

impl PartialEq for UnreadCredentials {
    fn eq(&self, o: &UnreadCredentials) -> bool {
        self.proof == o.proof && self.sync.verifying_key() == o.sync.verifying_key() && self.deposit == o.deposit && self.claims == o.claims
    }
}

/// One S kept unread as of the last settle.
#[derive(Clone, Debug, PartialEq)]
pub struct Kept {
    /// Its head moved to a step whose sync key no held secret derives (spec/sync-judgement.md §6
    /// Stranded): it opens S nowhere but keeps its store.
    pub stranded: bool,
    /// `None` while stranded or before any step is registered.
    pub credentials: Option<Arc<UnreadCredentials>>,
}

/// What unread stands on: the engine's sync records, sync set and removal notices, the store's
/// path and own entries of S, and the two acts it does (shredding S, dropping a record). `Cx` is
/// the product's; every value read is a memo or a stamped store read, so `Effects` follows it.
pub trait Ground {
    fn sync_set(&mut self) -> Result<Arc<SyncSet>>;
    fn sync_records(&mut self) -> Result<Arc<BTreeMap<Tid, SyncRecord>>>;
    fn removal_notices(&mut self) -> Result<Arc<Vec<RemovalNotice>>>;
    /// The path registered with this node for S (its head last).
    fn path(&mut self, s: &SyncId) -> Result<Option<Arc<Path>>>;
    /// The entries this node logged itself under S (its deposits).
    fn own_entries(&mut self, s: &SyncId) -> Result<Vec<BlobId>>;
    /// Leaving S: its entries' keys and wraps erased.
    fn shred(&mut self, s: &SyncId) -> Result<()>;
    fn drop_sync_record(&mut self, thing: &Tid) -> Result<()>;
}

/// Whether a source of S showed `b` present by its stream (spec/sync-set.md §3: what a node
/// keeping S unread waits for before leaving). Stamped reads, so a leaving S is judged again when
/// presence moves.
pub trait Sources {
    fn present(&self, s: &SyncId, b: &BlobId) -> bool;
}

impl Ground for Cx<'_> {
    fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        Ok(self.engine.sync_set()?)
    }
    fn sync_records(&mut self) -> Result<Arc<BTreeMap<Tid, SyncRecord>>> {
        Ok(self.engine.sync_records()?)
    }
    fn removal_notices(&mut self) -> Result<Arc<Vec<RemovalNotice>>> {
        Ok(self.engine.removal_notices()?)
    }
    fn path(&mut self, s: &SyncId) -> Result<Option<Arc<Path>>> {
        Ok(Store::path(self.store, s))
    }
    fn own_entries(&mut self, s: &SyncId) -> Result<Vec<BlobId>> {
        Ok(self.store.entries(s).filter(|e| e.own).map(|e| e.blob).collect())
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.store.shred(s)
    }
    fn drop_sync_record(&mut self, thing: &Tid) -> Result<()> {
        Ok(self.engine.drop_sync_record(thing)?)
    }
}

/// A judgement of one S.
#[derive(Clone, Debug, PartialEq)]
enum Verdict {
    Keep(Kept),
    /// A removal notice verified: drop the thing's sync IDs at once.
    Stop,
    /// Unlisted and every own entry is present at a source.
    Leave,
}

#[derive(Clone)]
pub struct Unread {
    set: Effects<(), Arc<SyncSet>>,
    record_map: Effects<(), Arc<BTreeMap<Tid, SyncRecord>>>,
    notice_list: Effects<(), Arc<Vec<RemovalNotice>>>,
    /// S kept unread by the sync set, and its thing.
    listed: Stamped<SyncId, Tid>,
    records: Stamped<Tid, SyncRecord>,
    notices: Stamped<SyncId, Vec<RemovalNotice>>,
    /// Each S followed (listed, or leaving) and its thing.
    things: BTreeMap<SyncId, Tid>,
    judged: Effects<SyncId, Verdict>,
    kept: Stamped<SyncId, Kept>,
}

impl Default for Unread {
    fn default() -> Self {
        let mut u = Unread {
            set: Effects::new("unread: sync set"),
            record_map: Effects::new("unread: sync records"),
            notice_list: Effects::new("unread: removal notices"),
            listed: Stamped::default(),
            records: Stamped::default(),
            notices: Stamped::default(),
            things: BTreeMap::new(),
            judged: Effects::new("unread: judged"),
            kept: Stamped::default(),
        };
        u.set.want(());
        u.record_map.want(());
        u.notice_list.want(());
        u
    }
}

impl std::fmt::Debug for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unread").field("things", &self.things).finish_non_exhaustive()
    }
}

impl Unread {
    /// S's credentials while it is kept unread and not stranded (stamped read).
    pub fn credentials(&self, s: &SyncId) -> Option<Arc<UnreadCredentials>> {
        self.kept.get(s).and_then(|k| k.credentials.clone())
    }

    /// Whether S is kept unread here and stranded (stamped read).
    pub fn stranded(&self, s: &SyncId) -> bool {
        self.kept.get(s).is_some_and(|k| k.stranded)
    }

    /// Whether S is kept unread here: listed, or leaving and still waiting (stamped read).
    pub fn keeps(&self, s: &SyncId) -> bool {
        self.kept.contains_key(s)
    }

    /// Stops on a verified removal, strands on a head move, leaves when unlisted; whether
    /// anything another module reads changed.
    pub fn settle(&mut self, g: &mut impl Ground, sources: &impl Sources) -> Result<bool> {
        let mut acted = false;
        let set = match whole(&mut self.set, || g.sync_set()) {
            Err(e) if facade_not_built(&e) => return Ok(false),
            r => r?,
        };
        if let Some(set) = set {
            acted |= self.follow_set(&set);
        }
        if let Some(records) = whole(&mut self.record_map, || g.sync_records())? {
            mirror(&mut self.records, records.iter().map(|(t, r)| (*t, r.clone())));
        }
        if let Some(list) = whole(&mut self.notice_list, || g.removal_notices())? {
            let mut by: BTreeMap<SyncId, Vec<RemovalNotice>> = BTreeMap::new();
            for n in list.iter() {
                by.entry(n.sync_id).or_default().push(n.clone());
            }
            mirror(&mut self.notices, by);
        }
        for s in self.judged.due() {
            let Some(&thing) = self.things.get(&s) else {
                self.judged.unwant(&s);
                continue;
            };
            let (listed, records, notices) = (&self.listed, &self.records, &self.notices);
            let mut failed = None;
            let moved = self.judged.settle(&s, || match judge(g, sources, listed, records, notices, &s, &thing) {
                Ok(v) => v,
                Err(e) => {
                    failed = Some(e);
                    Verdict::Leave
                }
            });
            if let Some(e) = failed {
                // due again: judged anew after the failure is dealt with
                self.judged.unwant(&s);
                self.judged.want(s);
                return Err(e);
            }
            let Some((_, now)) = moved else { continue };
            acted = true;
            match now {
                Verdict::Keep(k) => {
                    self.kept.insert(s, k);
                }
                Verdict::Leave => {
                    g.shred(&s)?;
                    self.forget(&s);
                }
                Verdict::Stop => {
                    // removed by another: every sync ID of the thing goes at once
                    let mut ids: Vec<SyncId> = self.records.get(&thing).map(|r| r.sync_ids.clone()).unwrap_or_default();
                    ids.push(s);
                    ids.sort();
                    ids.dedup();
                    for id in &ids {
                        if self.things.contains_key(id) || *id == s {
                            g.shred(id)?;
                            self.forget(id);
                        }
                    }
                    g.drop_sync_record(&thing)?;
                }
            }
        }
        Ok(acted)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }

    /// The sync set moved: S newly kept unread is followed, S no longer listed is judged again
    /// (leaving), S raised to read is no longer this module's (its store stays).
    fn follow_set(&mut self, set: &SyncSet) -> bool {
        let mut acted = false;
        let unread: BTreeMap<SyncId, Tid> = set.ids.iter().filter(|(_, (_, h))| *h == Holding::Unread).map(|(s, (t, _))| (*s, *t)).collect();
        for s in mirror(&mut self.listed, unread) {
            match (self.listed.get(&s), set.ids.get(&s)) {
                (Some(&t), _) => {
                    self.things.insert(s, t);
                    self.judged.want(s);
                }
                (None, Some((_, Holding::Read))) => {
                    acted |= self.kept.contains_key(&s);
                    self.forget(&s);
                }
                (None, _) => {}
            }
        }
        acted
    }

    fn forget(&mut self, s: &SyncId) {
        self.judged.unwant(s);
        self.things.remove(s);
        self.listed.remove(s);
        if self.kept.contains_key(s) {
            self.kept.remove(s);
        }
    }
}

/// A whole value read through its one `Effects` key: `Some` when it moved.
fn whole<T: Default + PartialEq>(fx: &mut Effects<(), Arc<T>>, f: impl FnOnce() -> Result<Arc<T>>) -> Result<Option<Arc<T>>> {
    if fx.due().is_empty() {
        return Ok(None);
    }
    let mut failed = None;
    let moved = fx.settle(&(), || {
        f().unwrap_or_else(|e| {
            failed = Some(e);
            Arc::default()
        })
    });
    if let Some(e) = failed {
        fx.unwant(&());
        fx.want(());
        return Err(e);
    }
    Ok(moved.map(|(_, now)| now))
}

/// The engine facade's call is not built yet (branch sync-facade): unread does nothing until it
/// is. Goes when the facade lands.
fn facade_not_built(e: &Error) -> bool {
    matches!(e, Error::Engine(osis_engine::Error::NotBuilt(_)))
}

/// Writes `to` to hold exactly `from`, touching only keys that differ; the keys written.
fn mirror<K: Ord + Clone + std::hash::Hash, V: PartialEq>(to: &mut Stamped<K, V>, from: impl IntoIterator<Item = (K, V)>) -> Vec<K> {
    let from: BTreeMap<K, V> = from.into_iter().collect();
    let gone: Vec<K> = to.keys().filter(|k| !from.contains_key(*k)).cloned().collect();
    let mut wrote = Vec::new();
    for k in gone {
        to.remove(&k);
        wrote.push(k);
    }
    for (k, v) in from {
        if to.get(&k) != Some(&v) {
            wrote.push(k.clone());
            to.insert(k, v);
        }
    }
    osis_base::costs::count("unread: mirrored", wrote.len() as u64);
    wrote
}

/// One S's judgement from its own keys only.
fn judge(
    g: &mut impl Ground,
    sources: &impl Sources,
    listed: &Stamped<SyncId, Tid>,
    records: &Stamped<Tid, SyncRecord>,
    notices: &Stamped<SyncId, Vec<RemovalNotice>>,
    s: &SyncId,
    thing: &Tid,
) -> Result<Verdict> {
    osis_base::costs::count("unread: judged", 1);
    let secrets: Vec<(VerifyingKey, &Secret32)> = records.get(thing).map(|r| r.secrets.values().map(|x| (label_role_key(LabelRole::Sync, x).verifying_key(), x)).collect()).unwrap_or_default();
    let path = g.path(s)?;
    let steps = path.as_ref().map(|p| p.steps.as_slice()).unwrap_or_default();
    if let Some(ns) = notices.get(s)
        && ns.iter().any(|n| removal_verifies(n, steps, &secrets))
    {
        return Ok(Verdict::Stop);
    }
    if listed.get(s).is_none() {
        let own = g.own_entries(s)?;
        if own.iter().all(|b| sources.present(s, b)) {
            return Ok(Verdict::Leave);
        }
    }
    let Some((head, claims)) = steps.last() else { return Ok(Verdict::Keep(Kept { stranded: false, credentials: None })) };
    let Some((_, secret)) = secrets.iter().find(|(k, _)| *k == head.keys.sync) else {
        return Ok(Verdict::Keep(Kept { stranded: true, credentials: None }));
    };
    let credentials = UnreadCredentials {
        sync: label_role_key(LabelRole::Sync, secret),
        proof: Secret32::from_bytes(sync_proof(&label_role_seed(LabelRole::Sync, secret))),
        deposit: head.keys.deposit,
        claims: claims.clone(),
    };
    Ok(Verdict::Keep(Kept { stranded: false, credentials: Some(Arc::new(credentials)) }))
}

/// spec/sync-judgement.md §6 Stops: the notice's signature verifies under the delete key of a
/// step on the path from the newest step whose sync secret is held up to the head (from the
/// genesis step when none is held).
fn removal_verifies(n: &RemovalNotice, steps: &[(osis_label::Step, Option<ClaimSet>)], secrets: &[(VerifyingKey, &Secret32)]) -> bool {
    let from = steps.iter().rposition(|(st, _)| secrets.iter().any(|(k, _)| *k == st.keys.sync)).unwrap_or(0);
    steps.get(from..).unwrap_or_default().iter().any(|(st, _)| {
        osis_base::costs::count("unread: verifies", 1);
        verify_removal(&st.keys.delete, &n.sync_id, &n.recipient, &n.commit, &n.sig).is_ok()
    })
}

/// Not built: a source's `known` (streams). Until it is, no own entry counts as present, so a
/// node keeping S unread that logged entries there waits.
impl Sources for Streams {
    fn present(&self, s: &SyncId, b: &BlobId) -> bool {
        let _ = (s, b);
        false
    }
}
