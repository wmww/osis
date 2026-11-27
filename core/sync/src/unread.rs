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
    /// Its head is past its keys (spec/sync-judgement.md §6 Stops): S is asked of every peer by
    /// role (spec/sync-opens.md §5 ByRole), a reader there telling it the rotation's box.
    pub stopped: bool,
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
    /// What its head says of the public (`Engine::public_head`).
    pub public: Public,
}

/// What a node keeping S unread reads of the public at its head (spec/sync.md §3 Holders by
/// copies, spec/sync-opens.md §4 Admissible).
#[derive(Clone, Debug, PartialEq)]
pub enum Public {
    /// No step registered yet: nothing said.
    NoHead,
    /// The head lists no public entry: the public holds nothing there as this node knows it.
    Unlisted,
    /// The head with its claim set (`at`), which lists S's public entry: the public holds sync there,
    /// and the entry's box gives its sync secret (a head past this node's keys among such).
    /// `reads`: the head bears a sync epoch of the latest number held and is not the head it
    /// was lowered to sync at, so the node also reads S by the box's read secrets. A head behind
    /// a later sync epoch held is one it knows superseded and proves nothing (a public's removal
    /// since included), and so, for reading, is the head it was lowered to sync at (it read there
    /// what ended the public's read, a lowering of it included, which rotates no sync epoch): it
    /// waits for the Register moving it.
    Listed { at: Box<(Step, ClaimSet)>, reads: bool },
}

/// What one S is judged on, every value read by key (spec/sync-judgement.md §6).
pub struct Judged<'a> {
    pub s: &'a SyncId,
    /// The sync secrets of S's thing held here, by epoch.
    pub secrets: &'a [(osis_crypto::Epoch, Secret32)],
    /// S's verified path as Registers gave it (its head last).
    pub steps: &'a [(Step, Option<ClaimSet>)],
    /// The head this node was lowered at from opening S to keeping it unread, if it was
    /// (`Store::lowered_at`, durable).
    pub lowered_at: Option<&'a StepId>,
}

/// spec/sync-judgement.md §6 (keeps, stops), over plain values.
pub fn judge(j: &Judged) -> Kept {
    osis_base::costs::count("unread: judged", 1);
    // each sync secret held, newest first (distinct), with its sync key and proof
    let mut secrets: Vec<(&osis_crypto::Epoch, &Secret32)> = j.secrets.iter().map(|(e, x)| (e, x)).collect();
    secrets.sort_by(|a, b| b.0.cmp(a.0));
    let mut seen = BTreeSet::new();
    secrets.retain(|(_, x)| seen.insert(*x.expose()));
    // the sync keys of the latest sync epoch number held: concurrent rotations give several, and
    // a head bearing any is superseded by none held (no order among them decides)
    let latest = secrets.first().map(|(e, _)| e.n());
    let current: Vec<_> = secrets.iter().filter(|(e, _)| Some(e.n()) == latest).map(|(_, x)| role_key(RoleKey::Sync, x).verifying_key()).collect();
    let held: Vec<(SigningSecret, Secret32)> = secrets.into_iter().map(|(_, x)| (role_key(RoleKey::Sync, x), Secret32::from_bytes(sync_proof(&role_key_seed(RoleKey::Sync, x))))).collect();
    let keep = |stranded: bool, credentials: Option<UnreadCredentials>| Kept { stranded, credentials: credentials.map(Arc::new), public: Public::NoHead };
    let Some(head) = j.steps.last() else {
        // no step registered yet: each sync secret it holds counts as its step, so a reader's
        // test finds S here and registers its path, and a box at a self-made epoch hides no
        // genuine one (spec/sync-opens.md §4 Admissible)
        return keep(false, (!held.is_empty()).then(|| UnreadCredentials { step: None, keys: held, deposit: None, claims: None, stopped: false }));
    };
    let public = |reads: bool| match head.1.as_ref().filter(|c| c.lists_public(j.s)) {
        Some(c) => Public::Listed { at: Box::new((head.0.clone(), c.clone())), reads },
        None => Public::Unlisted,
    };
    if let Some(k) = held.iter().find(|(k, _)| k.verifying_key() == head.0.keys.sync) {
        let mut kept = keep(false, Some(UnreadCredentials { step: Some(head.0.id()), keys: vec![k.clone()], deposit: Some(head.0.keys.deposit), claims: head.1.clone(), stopped: false }));
        kept.public = public(current.contains(&head.0.keys.sync) && j.lowered_at != Some(&head.0.id()));
        return kept;
    }
    // its head is past its keys: it shows only the secrets no step of its path bears (a re-grant
    // past its head, which a reader holding it moves it to), so a node removed shows nothing;
    // where the head lists the public entry, its box gives the head's sync secret
    let keys: Vec<_> = held.into_iter().filter(|(k, _)| !j.steps.iter().any(|(st, _)| st.keys.sync == k.verifying_key())).collect();
    let mut kept = keep(true, (!keys.is_empty()).then_some(UnreadCredentials { step: None, keys, deposit: None, claims: None, stopped: true }));
    kept.public = public(false);
    kept
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
            // what the head says of the public: listed, it holds sync there (its box's sync
            // secret taken) and, `reads`, S becomes read by the box (`syncs` follows it)
            let path = || -> Result<Vec<_>> { Ok(cx.store.path(&s)?.map(|p| p.steps.iter().map(|(st, _)| st.id()).collect()).unwrap_or_default()) };
            let read = match &k.public {
                Public::NoHead => false,
                Public::Unlisted => {
                    let path = path()?;
                    cx.engine.public_head(&s, None, false, &path)?
                }
                Public::Listed { at, reads } => {
                    let path = path()?;
                    cx.engine.public_head(&s, Some((&at.0, &at.1)), *reads, &path)?
                }
            };
            if read {
                osis_base::costs::count("unread: read by its head's public entry", 1);
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
    let lowered_at = cx.store.lowered_at(s)?;
    Ok(judge(&Judged { s, secrets: &secrets, steps: path.as_ref().map(|p| p.steps.as_slice()).unwrap_or_default(), lowered_at: lowered_at.as_ref() }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::{Judged, judge};
    use osis_base::{Role, Tid};
    use osis_blob::{Parent, Reader, StepKeys, genesis_sync_id, register};
    use osis_crypto::{Epoch, RoleKey, Secret32, SeededRng, role_key};

    // spec/sync-opens.md §4 (Admissible: keeping S unread, the head bears a sync epoch no held one
    // is later than): concurrent rotations give two sync epochs of one number; a head listing the
    // public that bears either is taken (failed with the newest by full epoch order: a head bearing
    // the lesser nonce was taken nowhere, waiting on a rotation nothing owes). One held epoch of a
    // later number makes both heads superseded.
    #[test]
    fn a_head_at_either_concurrent_sync_epoch_gives_its_public_entry() {
        let t = Tid::from_bytes([7; 15]);
        let sec = |b: u8| Secret32::from_bytes([b; 32]);
        let (admin, write, deposit, read) = (sec(1), sec(2), sec(3), sec(4));
        let held: Vec<(Epoch, Secret32)> = [(3, 10), (3, 11), (4, 12)].into_iter().map(|(n, b)| (Epoch::derive(&t, Role::Sync, n, &sec(b)).unwrap(), sec(b))).collect();
        let s = genesis_sync_id(&admin);
        for (i, (e, x)) in held.iter().take(2).enumerate() {
            let keys = StepKeys::derive(x, &write, &admin, &deposit, &s);
            let read_at = (&t, Epoch::derive(&t, Role::Read, 3, &read).unwrap(), &read);
            let step = register(Parent::Genesis(&role_key(RoleKey::Delete, &admin)), keys, &[Reader::Public { reads: true }], read_at, (*e, x), &mut SeededRng::from_u64(0)).unwrap();
            let steps = [(step.0, Some(step.1))];
            let reads = |k: super::Kept| matches!(k.public, super::Public::Listed { reads: true, .. });
            assert!(reads(judge(&Judged { s: &s, secrets: &held[..2], steps: &steps, lowered_at: None })), "head at concurrent epoch {i}");
            assert!(!reads(judge(&Judged { s: &s, secrets: &held, steps: &steps, lowered_at: None })), "head at {i} behind a later epoch");
            let head = steps.first().map(|x| x.0.id());
            assert!(!reads(judge(&Judged { s: &s, secrets: &held[..2], steps: &steps, lowered_at: head.as_ref() })), "head at {i} it was lowered at");
        }
    }
}
