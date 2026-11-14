//! Judgement for kept-unread sync IDs (spec/sync-judgement.md §6, spec/sync-set.md §3).
//!
//! Principle: a node keeping S unread decides its own grant by the boxes sealed to it, and by
//! nothing else. It holds no engine state of what S carries: its inputs are the engine facade's
//! sync set (per thing) and sync record, the store's path and own entries of S, and whether a
//! source holds an own entry (`Sources`). It keeps S while its head's sync key is one a held
//! secret derives; at a head whose key none derives it drops its copy and takes nothing
//! (`Store::set_unheld`), showing only the secrets no step of its path bears, so a reader holding
//! one registers its path onward (a re-grant past its head); unlisted, it leaves once each entry
//! it logged itself is present at a source, keeping its record. Model:
//! core/test/tla/net/NetKeep.tla.
//!
//! Work follows change: the synced group's closure (`sync_things`) through one `Effects` key,
//! diffed on change (O(closure) per closure change), each thing's `thing_sync` through its own,
//! and each S's judgement through one `Effects` key that reads its record, path and own entries
//! by key, so a head move or a box judges only its own S.
//!
//! State: `kept` (per S: stranded, credentials), which `opens` and `status` read stamped.
//! Nothing durable of its own: a start settles every key once.

use crate::types::{Cx, Result};
use osis_base::memo::{Effects, Stamped};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_crypto::kdf::sync_proof;
use osis_crypto::{LabelRole, Secret32, SigningSecret, VerifyingKey, label_role_key, label_role_seed};
use osis_engine::sync::{SyncRecord, ThingSync};
use osis_label::{ClaimSet, Step, StepId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What a node keeping S unread opens and acts with, from its sync record and its store's head
/// (spec/sync-opens.md §4: it shows its step's sync key, the sync proof of it, and its head's
/// deposit key and claim set).
#[derive(Clone, Debug)]
pub struct UnreadCredentials {
    /// Its step (spec/sync-opens.md §4 Admissible): the head when a held secret derives its sync
    /// key, else none (each sync secret it shows counts as one).
    pub step: Option<StepId>,
    /// The sync key and sync proof (spec/sync-ids.md §2) of each of its steps: the head's alone;
    /// else those of every sync secret held whose sync key no step of its path bears (with no
    /// head, every one), newest first. A Hit on a sync key is answered by that key
    /// (spec/sync-opens.md §5 Proof).
    pub keys: Vec<(SigningSecret, Secret32)>,
    /// The head's deposit key (public: a node keeping S unread signs no deposit).
    pub deposit: Option<VerifyingKey>,
    /// The head's claim set.
    pub claims: Option<ClaimSet>,
}

impl PartialEq for UnreadCredentials {
    fn eq(&self, o: &UnreadCredentials) -> bool {
        self.step == o.step
            && self.keys.len() == o.keys.len()
            && self.keys.iter().zip(&o.keys).all(|((a, p), (b, q))| p == q && a.verifying_key() == b.verifying_key())
            && self.deposit == o.deposit && self.claims == o.claims
    }
}

/// One S kept unread as of the last settle.
#[derive(Clone, Debug, PartialEq)]
pub struct Kept {
    /// Its head is at a step whose sync key no held secret derives (spec/sync-judgement.md §6;
    /// stranded, spec/permissions.md §4): it holds no entry of S and takes none.
    pub stranded: bool,
    /// `None` when it shows no sync key.
    pub credentials: Option<Arc<UnreadCredentials>>,
}

/// Whether a source of S showed `b` present by its stream (spec/sync-set.md §3: what a node
/// keeping S unread waits for before leaving). Stamped reads, so a leaving S is judged again when
/// presence moves.
pub trait Sources {
    fn present(&self, s: &SyncId, b: &BlobId) -> bool;
}

/// A judgement of one S.
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    Keep(Kept),
    /// Unlisted and every own entry is present at a source.
    Leave,
}

/// What one S is judged on, every value read by key (spec/sync-judgement.md §6).
pub struct Judged<'a> {
    /// The sync set lists S kept unread.
    pub listed: bool,
    /// The thing's sync record (sync secrets by epoch).
    pub record: Option<&'a SyncRecord>,
    /// S's verified path as Registers gave it (its head last).
    pub steps: &'a [(Step, Option<ClaimSet>)],
    /// Unlisted only: each entry this node logged itself under S is present at a source.
    pub own_elsewhere: bool,
}

/// spec/sync-judgement.md §6 (keeps, stops) and spec/sync-set.md §3 (leaving), over plain values.
pub fn judge(j: &Judged) -> Verdict {
    osis_base::costs::count("unread: judged", 1);
    if !j.listed && j.own_elsewhere {
        return Verdict::Leave;
    }
    // each sync secret held, newest first, with its sync key and proof
    let held: Vec<(SigningSecret, Secret32)> = j
        .record
        .map(|r| r.secrets.values().rev().map(|x| (label_role_key(LabelRole::Sync, x), Secret32::from_bytes(sync_proof(&label_role_seed(LabelRole::Sync, x))))).collect())
        .unwrap_or_default();
    let keep = |stranded: bool, credentials: Option<UnreadCredentials>| Verdict::Keep(Kept { stranded, credentials: credentials.map(Arc::new) });
    let Some(head) = j.steps.last() else {
        // no step registered yet: each sync secret it holds counts as its step, so a reader's
        // test finds S here and registers its path, and a box at a self-made epoch hides no
        // genuine one (spec/sync-opens.md §4 Admissible)
        return keep(false, (!held.is_empty()).then(|| UnreadCredentials { step: None, keys: held, deposit: None, claims: None }));
    };
    if let Some(k) = held.iter().find(|(k, _)| k.verifying_key() == head.0.keys.sync) {
        return keep(false, Some(UnreadCredentials { step: Some(head.0.id()), keys: vec![k.clone()], deposit: Some(head.0.keys.deposit), claims: head.1.clone() }));
    }
    // its head is past its keys: it shows only the secrets no step of its path bears (a re-grant
    // past its head, which a reader holding it moves it to), so a node removed shows nothing
    let keys: Vec<_> = held.into_iter().filter(|(k, _)| !j.steps.iter().any(|(st, _)| st.keys.sync == k.verifying_key())).collect();
    keep(true, (!keys.is_empty()).then_some(UnreadCredentials { step: None, keys, deposit: None, claims: None }))
}

#[derive(Clone)]
pub struct Unread {
    /// The synced group's closure (`sync_things`), and its last value.
    closure: Effects<(), Arc<BTreeSet<Tid>>>,
    things: BTreeSet<Tid>,
    /// Each thing of the closure: how it is synced (`thing_sync`).
    thing: Effects<Tid, ThingSync>,
    /// The sync IDs each thing is kept unread under.
    thing_ids: BTreeMap<Tid, Vec<SyncId>>,
    /// S kept unread by the sync set, and its thing.
    listed: Stamped<SyncId, Tid>,
    /// Each S followed (listed, or leaving) and its thing.
    followed: BTreeMap<SyncId, Tid>,
    judged: Effects<SyncId, Verdict>,
    kept: Stamped<SyncId, Kept>,
}

impl Default for Unread {
    fn default() -> Self {
        let mut closure = Effects::new("unread: closure");
        closure.want(());
        Unread {
            closure,
            things: BTreeSet::new(),
            thing: Effects::new("unread: thing"),
            thing_ids: BTreeMap::new(),
            listed: Stamped::default(),
            followed: BTreeMap::new(),
            judged: Effects::new("unread: judged"),
            kept: Stamped::default(),
        }
    }
}

impl std::fmt::Debug for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unread").field("followed", &self.followed).finish_non_exhaustive()
    }
}

impl Unread {
    /// What S shows and tests while it is kept unread (stamped read).
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

    /// Keeps, drops its copy at a head past its keys, leaves when unlisted; whether anything
    /// another module reads changed.
    pub fn settle(&mut self, cx: &mut Cx, sources: &impl Sources) -> Result<bool> {
        let mut acted = false;
        if !self.closure.due().is_empty() {
            let engine = &mut *cx.engine;
            if let Some((_, now)) = settled(&mut self.closure, &(), Arc::default(), || Ok(engine.sync_things()?))? {
                let gone: Vec<Tid> = self.things.iter().filter(|t| !now.contains(*t)).copied().collect();
                for t in gone {
                    self.things.remove(&t);
                    self.thing.unwant(&t);
                    acted |= self.thing_moved(cx, &t, &ThingSync::Plain)?;
                }
                for t in now.iter() {
                    if self.things.insert(*t) {
                        self.thing.want(*t);
                    }
                }
            }
        }
        for t in self.thing.due() {
            let engine = &mut *cx.engine;
            let Some((_, now)) = settled(&mut self.thing, &t, ThingSync::Plain, || Ok(engine.thing_sync(&t)?))? else { continue };
            acted |= self.thing_moved(cx, &t, &now)?;
        }
        for s in self.judged.due() {
            let Some(&thing) = self.followed.get(&s) else {
                self.judged.unwant(&s);
                continue;
            };
            let listed = &self.listed;
            let Some((_, now)) = settled(&mut self.judged, &s, Verdict::Leave, || judge_s(cx, sources, listed, &s, &thing))? else { continue };
            acted = true;
            match now {
                Verdict::Keep(k) => {
                    // at a head past its keys its copy goes and it takes nothing (§6)
                    cx.store.set_unheld(&s, k.stranded)?;
                    self.kept.insert(s, k);
                }
                Verdict::Leave => {
                    cx.store.shred(&s)?;
                    self.forget(&s);
                }
            }
        }
        Ok(acted)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }

    /// Thing `t`'s sync moved: S newly kept unread is followed, S no longer listed is judged
    /// again (leaving), S raised to read is no longer this module's (its store stays).
    fn thing_moved(&mut self, cx: &mut Cx, t: &Tid, now: &ThingSync) -> Result<bool> {
        let mut acted = false;
        let ids: Vec<SyncId> = match now {
            ThingSync::Unread(ids) => ids.clone(),
            _ => Vec::new(),
        };
        let was = self.thing_ids.remove(t).unwrap_or_default();
        for s in was.iter().filter(|s| !ids.contains(s)) {
            self.listed.remove(s);
            if matches!(now, ThingSync::Read(r) if r.contains(s)) {
                acted |= self.kept.contains_key(s);
                cx.store.set_unheld(s, false)?;
                self.forget(s);
            }
        }
        for s in ids.iter().filter(|s| !was.contains(s)) {
            self.listed.insert(*s, *t);
            self.followed.insert(*s, *t);
            self.judged.want(*s);
        }
        if !ids.is_empty() {
            self.thing_ids.insert(*t, ids);
        }
        Ok(acted)
    }

    fn forget(&mut self, s: &SyncId) {
        self.judged.unwant(s);
        self.followed.remove(s);
        if self.listed.contains_key(s) {
            self.listed.remove(s);
        }
        if self.kept.contains_key(s) {
            self.kept.remove(s);
        }
    }
}

/// Runs `f` in an `Effects` settle and hands back its error, keeping the key due.
fn settled<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq>(fx: &mut Effects<K, V>, k: &K, fallback: V, f: impl FnOnce() -> Result<V>) -> Result<Option<(Option<V>, V)>> {
    let mut failed = None;
    let moved = fx.settle(k, || {
        f().unwrap_or_else(|e| {
            failed = Some(e);
            fallback
        })
    });
    if let Some(e) = failed {
        fx.unwant(k);
        fx.want(k.clone());
        return Err(e);
    }
    Ok(moved)
}

/// One S's judgement, reading its own keys only.
fn judge_s(cx: &mut Cx, sources: &impl Sources, listed: &Stamped<SyncId, Tid>, s: &SyncId, thing: &Tid) -> Result<Verdict> {
    let record = cx.engine.sync_record(thing)?;
    let path = cx.store.path(s)?;
    let listed = listed.get(s).is_some();
    let own_elsewhere = !listed && cx.store.entries(s)?.into_iter().filter(|e| e.own).all(|e| sources.present(s, &e.blob));
    Ok(judge(&Judged { listed, record: record.as_deref(), steps: path.as_ref().map(|p| p.steps.as_slice()).unwrap_or_default(), own_elsewhere }))
}

