//! Judgement for kept-unread sync IDs (spec/sync-judgement.md §6, spec/sync-set.md §3).
//!
//! Principle: a node keeping S unread holds the sync secrets of S's thing that its boxes give and
//! those it held when it stopped reading (spec/sync.md §3); it holds no engine
//! state of what S carries. Its inputs are the
//! sync IDs this node syncs kept unread, those secrets and the store's path of S. It keeps S
//! while its head's sync key is one a held secret derives; at a head whose key none derives it
//! drops its copy and takes nothing (`Store::set_unheld`), showing only the secrets no step of its
//! path bears, so a reader holding one registers its path onward (a re-grant past its head).
//! Leaving is `leave`'s: S is kept here while it waits there. Model: core/test/tla/net/NetKeep.tla.
//!
//! Work follows change: the sync IDs this node syncs kept unread (`set::SyncsFollow`, O(moved)),
//! and each S's judgement through one `Effects` key that reads its secrets and path by key, so a
//! head move or a box judges only its own S.
//!
//! State: `kept` (per S: stranded, credentials), which `opens` and `status` read stamped.
//! Nothing durable of its own: a start settles every key once.

use crate::types::{Cx, Result};
use osis_base::memo::{Effects, Stamped};
use osis_base::SyncId;
use osis_crypto::kdf::sync_proof;
use osis_crypto::{RoleKey, Secret32, SigningSecret, VerifyingKey, role_key, role_key_seed};
use osis_engine::sync::Holding;
use osis_blob::{ClaimSet, Step, StepId};
use std::collections::BTreeSet;
use std::sync::Arc;

/// What a node keeping S unread opens and acts with, from its held sync secrets and its store's head
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
    /// Its head with its claim set, where the set lists S's public entry and the head bears the
    /// newest sync epoch held: the node reads S by that entry's open box (spec/sync-opens.md §4
    /// Admissible). A head behind a newer sync epoch held is one it knows superseded and proves
    /// nothing (a public's removal since included): it waits for the Register moving it.
    pub public: Option<(Step, ClaimSet)>,
}

/// What one S is judged on, every value read by key (spec/sync-judgement.md §6).
pub struct Judged<'a> {
    pub s: &'a SyncId,
    /// The sync secrets of S's thing held here, by epoch.
    pub secrets: &'a [(osis_crypto::Epoch, Secret32)],
    /// S's verified path as Registers gave it (its head last).
    pub steps: &'a [(Step, Option<ClaimSet>)],
}

/// spec/sync-judgement.md §6 (keeps, stops), over plain values.
pub fn judge(j: &Judged) -> Kept {
    osis_base::costs::count("unread: judged", 1);
    // each sync secret held, newest first (distinct), with its sync key and proof
    let mut secrets: Vec<(&osis_crypto::Epoch, &Secret32)> = j.secrets.iter().map(|(e, x)| (e, x)).collect();
    secrets.sort_by(|a, b| b.0.cmp(a.0));
    let mut seen = BTreeSet::new();
    secrets.retain(|(_, x)| seen.insert(*x.expose()));
    let newest = secrets.first().map(|(_, x)| role_key(RoleKey::Sync, x).verifying_key());
    let held: Vec<(SigningSecret, Secret32)> = secrets.into_iter().map(|(_, x)| (role_key(RoleKey::Sync, x), Secret32::from_bytes(sync_proof(&role_key_seed(RoleKey::Sync, x))))).collect();
    let keep = |stranded: bool, credentials: Option<UnreadCredentials>| Kept { stranded, credentials: credentials.map(Arc::new), public: None };
    let Some(head) = j.steps.last() else {
        // no step registered yet: each sync secret it holds counts as its step, so a reader's
        // test finds S here and registers its path, and a box at a self-made epoch hides no
        // genuine one (spec/sync-opens.md §4 Admissible)
        return keep(false, (!held.is_empty()).then(|| UnreadCredentials { step: None, keys: held, deposit: None, claims: None }));
    };
    if let Some(k) = held.iter().find(|(k, _)| k.verifying_key() == head.0.keys.sync) {
        let public = head.1.as_ref().filter(|c| c.lists_public(j.s) && newest == Some(head.0.keys.sync)).map(|c| (head.0.clone(), c.clone()));
        let mut kept = keep(false, Some(UnreadCredentials { step: Some(head.0.id()), keys: vec![k.clone()], deposit: Some(head.0.keys.deposit), claims: head.1.clone() }));
        kept.public = public;
        return kept;
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
                    if now.as_ref().is_some_and(|(_, h)| h.opens()) {
                        cx.store.set_unheld(&s, false)?;
                    }
                    if self.followed.remove(&s) {
                        self.judged.unwant(&s);
                        acted |= self.kept.remove(&s).is_some();
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
            // read by the public entry its head lists: S becomes read (`syncs` follows it)
            if let Some((head, claims)) = &k.public {
                cx.engine.take_public_entry(&s, head, claims)?;
            }
            self.kept.insert(s, k);
        }
        Ok(acted)
    }
}

/// One S's judgement, reading its own keys only.
fn judge_s(cx: &mut Cx, s: &SyncId) -> Result<Kept> {
    let secrets = cx.engine.kept_sync_secrets(s);
    let path = cx.store.path(s)?;
    Ok(judge(&Judged { s, secrets: &secrets, steps: path.as_ref().map(|p| p.steps.as_slice()).unwrap_or_default() }))
}
