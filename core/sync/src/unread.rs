//! Judgement for kept-unread sync IDs (spec/sync-judgement.md §6, spec/sync-set.md §3).
//!
//! Principle: a node keeping S unread trusts only its own account (spec/sync.md §3 Sync record):
//! it keeps the sync IDs its account's record keeps and holds the secrets the record and the
//! boxes payloads held give; it holds no engine state of what S carries. Its inputs are the sync
//! IDs this node syncs kept unread, the engine facade's records keeping S and the store's path of
//! S. It holds the secrets of the things S is synced for (`osis_engine::sync::kept_things`: those
//! tied to S when any is). For every thing keeping S, a step of the path bearing the sync key of
//! a held secret of it ties S to it and records that secret (`Engine::record_borne`), so the tie
//! is judged whichever thing S is synced for now. Model of the record:
//! core/test/tla/net/NetTrust.tla. It keeps S
//! while its head's sync key is one a held
//! secret derives; at a head whose key none derives it drops its copy and takes nothing
//! (`Store::set_unheld`), showing only the secrets no step of its path bears, so a reader holding
//! one registers its path onward (a re-grant past its head). At a closing head it drops its copy
//! and the record keeps S no more (`Engine::close_kept`), so S leaves the sync set. Leaving
//! (unlisted or closed) is `leave`'s: S is kept here while it waits there. Model: core/test/tla/net/NetKeep.tla.
//!
//! Work follows change: the sync IDs this node syncs kept unread (`set::SyncsFollow`, O(moved)),
//! and each S's judgement through one `Effects` key that reads its record and path by key, so a
//! head move or a box judges only its own S.
//!
//! State: `kept` (per S: stranded, credentials), which `opens` and `status` read stamped.
//! Nothing durable of its own: a start settles every key once.

use crate::types::{Cx, Result};
use osis_base::memo::{Effects, Stamped};
use osis_base::{SyncId, Tid, WallMs};
use osis_crypto::kdf::sync_proof;
use osis_crypto::{RoleKey, Secret32, SigningSecret, VerifyingKey, role_key, role_key_seed};
use osis_engine::sync::{Holding, SyncRecord};
use osis_blob::{ClaimSet, Step, StepId};
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
    /// Per thing keeping S, the sync keys of its held secrets that a step of its path bears,
    /// where the record lacks the tie or one of those secrets: what the account's sync record
    /// takes (spec/sync.md §3 Tied, A recorded secret).
    pub borne: BTreeMap<Tid, BTreeSet<[u8; 32]>>,
    /// Its head is a closing step (spec/sync-judgement.md §6 Closes): the account's sync record
    /// keeps S no more, for every thing keeping it, so S leaves (`leave` shreds it, path included).
    pub closed: bool,
}

/// What one S is judged on, every value read by key (spec/sync-judgement.md §6).
pub struct Judged<'a> {
    /// S itself.
    pub s: SyncId,
    /// The records keeping S, by thing (sync secrets by epoch, ties).
    pub records: &'a [(Tid, Arc<SyncRecord>)],
    /// S's verified path as Registers gave it (its head last).
    pub steps: &'a [(Step, Option<ClaimSet>)],
}

/// spec/sync-judgement.md §6 (keeps, stops), over plain values.
pub fn judge(j: &Judged) -> Kept {
    osis_base::costs::count("unread: judged", 1);
    // each sync secret held of the things S is synced for, newest first (distinct), with its
    // sync key and proof
    let mut secrets: Vec<(&osis_crypto::Epoch, &Secret32)> = osis_engine::sync::kept_things(&j.s, j.records).flat_map(|(_, r)| r.secrets.iter()).collect();
    secrets.sort_by(|a, b| b.0.cmp(a.0));
    let mut seen = BTreeSet::new();
    secrets.retain(|(_, x)| seen.insert(*x.expose()));
    let held: Vec<(SigningSecret, Secret32)> = secrets.into_iter().map(|(_, x)| (role_key(RoleKey::Sync, x), Secret32::from_bytes(sync_proof(&role_key_seed(RoleKey::Sync, x))))).collect();
    // of every thing keeping S, what a step of the path bears that its record lacks
    let on_path = |k: &VerifyingKey| j.steps.iter().any(|(st, _)| st.keys.sync == *k);
    let mut borne = BTreeMap::new();
    for (t, r) in j.records {
        let keys: BTreeSet<[u8; 32]> = r.secrets.values().map(|x| role_key(RoleKey::Sync, x).verifying_key()).filter(on_path).map(|k| k.to_bytes()).collect();
        let lacks = !r.tied.contains(&j.s) || r.secrets.iter().any(|(e, x)| !r.recorded.contains(e) && on_path(&role_key(RoleKey::Sync, x).verifying_key()));
        if !keys.is_empty() && lacks {
            borne.insert(*t, keys);
        }
    }
    let keep = |stranded: bool, credentials: Option<UnreadCredentials>| Kept { stranded, credentials: credentials.map(Arc::new), borne: borne.clone(), closed: false };
    let Some(head) = j.steps.last() else {
        // no step registered yet: each sync secret it holds counts as its step, so a reader's
        // test finds S here and registers its path, and a box at a self-made epoch hides no
        // genuine one (spec/sync-opens.md §4 Admissible)
        return keep(false, (!held.is_empty()).then(|| UnreadCredentials { step: None, keys: held, deposit: None, claims: None }));
    };
    // closed: it drops its copy, shows nothing, and its record keeps S no more (§6 Closes)
    if head.0.is_closing() {
        return Kept { stranded: true, credentials: None, borne: BTreeMap::new(), closed: true };
    }
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
    /// The sync IDs this node syncs.
    syncs: crate::set::SyncsFollow,
    /// Each S kept unread (listed, or leaving and waiting).
    followed: BTreeSet<SyncId>,
    judged: Effects<SyncId, Kept>,
    kept: Stamped<SyncId, Kept>,
}

impl Default for Unread {
    fn default() -> Self {
        Unread { syncs: Default::default(), followed: BTreeSet::new(), judged: Effects::new("unread: judged"), kept: Stamped::default() }
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

    /// Keeps, or drops its copy at a head past its keys; whether anything another module reads
    /// changed.
    pub fn settle(&mut self, cx: &mut Cx) -> Result<bool> {
        let mut acted = false;
        for (s, _, now) in self.syncs.settle(cx.store) {
            match now {
                Some((_, Holding::Unread)) => {
                    if self.followed.insert(s) {
                        self.judged.want(s);
                    }
                }
                // raised to read: no longer this module's (its store stays, a copy it dropped is
                // fetched anew, also when dropped before a restart); stopped: shredded
                _ => {
                    if matches!(now, Some((_, Holding::Read))) {
                        cx.store.set_unheld(&s, false)?;
                    }
                    if self.followed.remove(&s) {
                        self.judged.unwant(&s);
                        if self.kept.contains_key(&s) {
                            self.kept.remove(&s);
                            acted = true;
                        }
                    }
                }
            }
        }
        for s in self.judged.due() {
            if !self.followed.contains(&s) {
                self.judged.unwant(&s);
                continue;
            }
            let Some((_, k)) = self.judged.try_settle(&s, || judge_s(cx, &s))? else { continue };
            acted = true;
            // at a head past its keys its copy goes and it takes nothing (§6)
            cx.store.set_unheld(&s, k.stranded)?;
            // a held secret a step of its path bears goes to the account's record, with the tie:
            // its own write moves the record, and the next judgement finds it there
            for (t, keys) in &k.borne {
                cx.engine.record_borne(t, &s, keys)?;
            }
            if k.closed {
                for (t, _) in cx.engine.kept_records(&s)? {
                    cx.engine.close_kept(&t, &s)?;
                }
            }
            self.kept.insert(s, k);
        }
        Ok(acted)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

/// One S's judgement, reading its own keys only.
fn judge_s(cx: &mut Cx, s: &SyncId) -> Result<Kept> {
    let records = cx.engine.kept_records(s)?;
    let path = cx.store.path(s)?;
    Ok(judge(&Judged { s: *s, records: &records, steps: path.as_ref().map(|p| p.steps.as_slice()).unwrap_or_default() }))
}
