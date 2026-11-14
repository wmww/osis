//! Kept unread (spec/sync-judgement.md §6, spec/sync-set.md §3): the judgement of one S over
//! plain values (`unread::judge`), as the module reads them from the engine facade and the store.
//! Each negative control of core/test/tla/net/NetKeep.tla has a test here that fails without its
//! rule. The module over a real engine (following the sync set, shredding, dropping the record,
//! work at n and 10n) is tests/it/keep.rs.

use osis_base::{CommitId, SyncId, Tid};
use osis_crypto::{Epoch, LabelRole, Secret32, Signature, SigningSecret, label_role_key};
use osis_engine::sync::{Path, RemovalNotice, SyncRecord};
use osis_label::{Step, StepKeys, sign_removal};
use osis_sync::unread::{Judged, Verdict, judge};
const ME: Tid = Tid::from_bytes([7; 15]);

fn sync_id(i: u32) -> SyncId {
    let mut b = [1u8; 16];
    b[..4].copy_from_slice(&i.to_le_bytes());
    SyncId(b)
}

fn epoch(e: u64) -> Epoch {
    Epoch::new(e, [0; 32]).unwrap()
}

fn secret(tag: u8, e: u64) -> Secret32 {
    let mut b = [tag; 32];
    b[..8].copy_from_slice(&e.to_le_bytes());
    Secret32::from_bytes(b)
}

/// Sync secret of epoch `e` (one sequence for every thing: each has its own sync ID).
fn sync_secret(e: u64) -> Secret32 {
    secret(0x51, e)
}

/// The delete (admin) key of step `e`.
fn delete_key(e: u64) -> SigningSecret {
    label_role_key(LabelRole::Delete, &secret(0xad, e))
}

/// Step `e` of `s`: epoch `e`'s sync and delete keys (unread checks no step signature: the store
/// verified the path when it took each Register).
fn step(s: SyncId, e: u64) -> Step {
    let other = label_role_key(LabelRole::Write, &secret(0x77, e)).verifying_key();
    Step {
        label: s,
        prev: None,
        keys: StepKeys { sync: label_role_key(LabelRole::Sync, &sync_secret(e)).verifying_key(), write: other, delete: delete_key(e).verifying_key(), deposit: other },
        step_key: [e as u8; 32],
        claims_hash: [0; 32],
        sig: Signature([0; 64]),
    }
}

/// A removal notice signed by `signer`, binding sync epoch `e` (the newest its sender boxed ME at).
fn notice(s: SyncId, signer: &SigningSecret, e: u64) -> RemovalNotice {
    let commit = CommitId([0xc0; 32]);
    RemovalNotice { sync_id: s, epoch: e, sig: sign_removal(signer, &s, &ME, &commit, e), recipient: ME, commit }
}

/// One S kept unread: its record's sync epochs, its registered path's steps, the notices held,
/// listed or not, and whether its own entries are present at a source.
#[derive(Clone)]
struct Keep {
    s: SyncId,
    held: Vec<u64>,
    path: Path,
    notices: Vec<RemovalNotice>,
    listed: bool,
    own_elsewhere: bool,
}

impl Keep {
    /// Holding the sync secrets of `held` epochs, its head at step 0.
    fn new(held: &[u64]) -> Keep {
        let s = sync_id(0);
        Keep { s, held: held.to_vec(), path: Path { steps: vec![(step(s, 0), None)] }, notices: Vec::new(), listed: true, own_elsewhere: false }
    }

    fn verdict(&self) -> Verdict {
        let record = SyncRecord { sync_ids: vec![self.s], secrets: self.held.iter().map(|e| (epoch(*e), sync_secret(*e))).collect() };
        judge(&Judged { listed: self.listed, record: Some(&record), notices: &self.notices, steps: &self.path.steps, own_elsewhere: self.own_elsewhere })
    }

    /// A Register moves S's head to step `e`.
    fn register(&mut self, e: u64) {
        self.path.steps.push((step(self.s, e), None));
    }

    fn notify(&mut self, signer: &SigningSecret, e: u64) {
        self.notices.push(notice(self.s, signer, e));
    }

    fn kept(&self) -> Option<osis_sync::unread::Kept> {
        match self.verdict() {
            Verdict::Keep(k) => Some(k),
            _ => None,
        }
    }

    fn opens(&self) -> bool {
        self.kept().is_some_and(|k| k.credentials.is_some())
    }

    fn stranded(&self) -> bool {
        self.kept().is_some_and(|k| k.stranded)
    }

    fn stops(&self) -> bool {
        self.verdict() == Verdict::Stop
    }
}

// spec/sync-judgement.md §6 (keeps): S stays while its synced group's closure lists the thing and
// a sync secret is held; it opens with its head's sync key, the sync proof of it and the head's
// deposit key.
#[test]
fn keeps_and_opens_by_head_spec_sync_judgement_6() {
    let k = Keep::new(&[0]);
    let c = k.kept().and_then(|k| k.credentials).expect("opens at its head");
    assert_eq!(c.sync.verifying_key(), step(sync_id(0), 0).keys.sync);
    assert_eq!(c.deposit, step(sync_id(0), 0).keys.deposit);
    assert_eq!(c.proof, Secret32::from_bytes(osis_crypto::kdf::sync_proof(&osis_crypto::label_role_seed(LabelRole::Sync, &sync_secret(0)))));
    assert!(!k.stranded());
}

// spec/sync-judgement.md §6 (stranded): a head moved to a step whose sync key no held secret
// derives strands S (kept, its store too), and a box of the new secret ends it. NetKeep `KN_drop`
// (a head move drops the store) fails this.
#[test]
fn head_move_strands_and_keeps_store_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    k.register(1);
    assert!(k.stranded(), "kept, stranded");
    k.held.push(1);
    assert!(!k.stranded());
    assert_eq!(k.kept().unwrap().credentials.unwrap().sync.verifying_key(), step(sync_id(0), 1).keys.sync);
}

// spec/sync-opens.md §4 (keeping S unread: shows its head's sync key): stranded, S opens by no
// older secret it holds. NetKeep `KN_open` (opens by any held secret) fails this.
#[test]
fn stranded_opens_by_no_older_key_spec_sync_opens_4() {
    let mut k = Keep::new(&[0]);
    assert!(k.opens());
    k.register(1);
    assert!(!k.opens(), "epoch 0's secret is held, but the head is step 1's");
}

// spec/sync-judgement.md §6 (stops): a notice signed by no delete key of the path changes
// nothing; a genuine one stops S. NetKeep `KN_sig` (the signature unchecked) fails this.
#[test]
fn forged_removal_changes_nothing_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    k.notify(&label_role_key(LabelRole::Delete, &secret(0xf0, 0)), 0);
    let other = notice(sync_id(0), &delete_key(0), 0);
    let sig = sign_removal(&delete_key(0), &sync_id(0), &Tid::from_bytes([8; 15]), &other.commit, 0);
    k.notices.push(RemovalNotice { sig, ..other.clone() });
    let sig = sign_removal(&delete_key(0), &sync_id(1), &ME, &other.commit, 0);
    k.notices.push(RemovalNotice { sig, ..other.clone() });
    let sig = sign_removal(&delete_key(0), &sync_id(0), &ME, &other.commit, 1);
    k.notices.push(RemovalNotice { sig, ..other });
    assert!(!k.stops() && k.opens(), "forged, or signed over another recipient, sync ID or epoch");
    k.notify(&delete_key(0), 0);
    assert!(k.stops());
}

// spec/sync-judgement.md §6 (stops): a removal signed at the step before the removing rotation
// still stops a node whose head a Register moved past it before the notice arrived (stranded at
// the new step). NetKeep `KF_late` (verifying under the head's delete key only) fails this.
#[test]
fn removal_signed_before_a_late_head_move_stops_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    k.register(1);
    assert!(k.stranded());
    k.notify(&delete_key(0), 0);
    assert!(k.stops());
}

// spec/sync-judgement.md §6 (stops): a notice that does not verify yet is judged again at each
// head move while held: one signed by the removing rotation's own step stops the node once that
// step is registered.
#[test]
fn held_removal_judged_again_at_head_move_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    k.notify(&delete_key(1), 0);
    assert!(!k.stops(), "step 1 not registered yet");
    k.register(1);
    assert!(k.stops());
}

// spec/sync-judgement.md §6 (stops): the path checked runs from the newest step whose sync secret
// is held: a notice signed by an older step's delete key does not stop a node holding a newer
// step's secret.
#[test]
fn removal_below_newest_held_step_ignored_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0, 1]);
    k.register(1);
    assert!(!k.stranded());
    k.notify(&delete_key(0), 1);
    assert!(!k.stops() && k.opens());
}

// spec/sync-judgement.md §6 (stops): a notice binding a sync epoch older than one held is stale: K
// removed at epoch 0 (the rotation to step 1 leaving it out) and re-granted at epoch 1 keeps S
// when the removal's notice arrives after the re-grant's box, before or after step 1 is
// registered; a removal of the re-grant stops it. NetKeep
// `KF_regrant` (no epoch bound) fails this.
#[test]
fn removal_notice_stale_after_regrant_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0, 1]);
    k.notify(&delete_key(0), 0);
    assert!(!k.stops(), "the re-grant's box came first");
    k.register(1);
    assert!(!k.stops() && k.opens());
    k.notify(&delete_key(1), 1);
    assert!(k.stops(), "removed from the re-grant");
}

// spec/sync-judgement.md §6 (stops): a node that stopped on its removal and is re-granted later
// keeps S again although the old notice is still in its inbox, before any step of its new secret
// is registered, at the old step alone, and once the new step is. NetKeep
// `KF_regrant` fails this.
#[test]
fn removal_notice_stale_after_stop_and_regrant_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    k.notify(&delete_key(0), 0);
    assert!(k.stops());
    // re-granted at epoch 1: the record holds that epoch only; the store was shredded
    k.held = vec![1];
    k.path.steps.clear();
    assert!(!k.stops());
    k.register(0);
    assert!(!k.stops() && k.stranded(), "re-granted, old notice held, step 1 not registered");
    k.register(1);
    assert!(!k.stops() && k.opens());
}

// spec/sync-judgement.md §6 (stops), spec/sync-hostile.md (inflated sync epochs): a box at a
// self-made sync epoch past every real one makes every notice stale: the node keeps S (a wrong
// keep, the stated limit), and a genuine notice it held counts once that box is gone.
#[test]
fn inflated_epoch_makes_removal_stale_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0, 1_000_000]);
    k.notify(&delete_key(0), 0);
    assert!(!k.stops() && k.opens(), "kept, opening by the head's secret");
    k.held = vec![0];
    assert!(k.stops());
}

// spec/sync-judgement.md §6 (stops), spec/wire.md §9 position 5: an epoch no step bears (a
// rotation boxing the holder before another rotation removed it, steps issued only for the
// newest epoch) still counts: the remover signs at the newest epoch it boxed the holder at, so
// the notice is at or past every held epoch and stops it.
#[test]
fn removal_after_an_unstepped_rotation_stops_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0, 1]);
    k.register(2);
    assert!(k.stranded());
    k.notify(&delete_key(2), 1);
    assert!(k.stops());
}

// spec/sync-judgement.md §6 (stops): holding the sync secret of no step on its path, a node takes
// a removal signed by its head's delete key only, not an older step's (which may be a removed
// admin's).
#[test]
fn removal_with_no_held_step_checks_head_only_spec_sync_judgement_6() {
    let mut k = Keep::new(&[2]);
    k.register(1);
    assert!(k.stranded());
    k.notify(&delete_key(0), 2);
    assert!(!k.stops(), "step 0 is below the head");
    k.notify(&delete_key(1), 2);
    assert!(k.stops());
}

// spec/sync-set.md §3 (leaving): unlisted, a node keeping S unread stays (and keeps serving)
// until each entry it logged itself is present at a source; a counted removal still stops it.
#[test]
fn leaves_once_own_entries_held_at_a_source_spec_sync_set_3() {
    let mut k = Keep::new(&[0]);
    k.listed = false;
    assert!(k.opens(), "its deposits not yet at a source");
    k.own_elsewhere = true;
    assert_eq!(k.verdict(), Verdict::Leave);
    k.listed = true;
    assert!(k.opens(), "listed: kept");
}
