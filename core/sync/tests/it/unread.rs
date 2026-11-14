//! Kept unread (spec/sync-judgement.md §6, spec/sync-set.md §3) on a fake ground: the engine's
//! sync set, sync records and removal notices and the store's path and own entries as stamped
//! values, so `Unread` runs as in a node while the engine facade is not built (sync-facade). Each
//! negative control of core/test/tla/net/NetKeep.tla has a test here that fails without its rule.

use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid};
use osis_crypto::{Epoch, LabelRole, Secret32, Signature, SigningSecret, label_role_key};
use osis_engine::sync::{Holding, Path, RemovalNotice, SyncRecord, SyncSet};
use osis_label::{Step, StepKeys, sign_removal};
use osis_sync::unread::{Ground, Sources, Unread};
use osis_sync::Result;
use std::collections::BTreeMap;
use std::sync::Arc;

const ME: Tid = Tid::from_bytes([7; 15]);

fn thing(i: u32) -> Tid {
    let mut b = [3u8; 15];
    b[..4].copy_from_slice(&i.to_le_bytes());
    Tid::from_bytes(b)
}

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

/// The engine and store as unread sees them, each a stamped value; `drop_sync_record` drops the
/// record and with it the sync set's entries of that thing, as the engine's memo would.
#[derive(Default)]
struct Fake {
    set: Stamped<(), Arc<SyncSet>>,
    records: Stamped<(), Arc<BTreeMap<Tid, SyncRecord>>>,
    notices: Stamped<(), Arc<Vec<RemovalNotice>>>,
    paths: Stamped<SyncId, Arc<Path>>,
    own: Stamped<SyncId, Vec<BlobId>>,
    shredded: Vec<SyncId>,
    dropped: Vec<Tid>,
}

impl Ground for Fake {
    fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        Ok(self.set.get(&()).cloned().unwrap_or_default())
    }
    fn sync_records(&mut self) -> Result<Arc<BTreeMap<Tid, SyncRecord>>> {
        Ok(self.records.get(&()).cloned().unwrap_or_default())
    }
    fn removal_notices(&mut self) -> Result<Arc<Vec<RemovalNotice>>> {
        Ok(self.notices.get(&()).cloned().unwrap_or_default())
    }
    fn path(&mut self, s: &SyncId) -> Result<Option<Arc<Path>>> {
        Ok(self.paths.get(s).cloned())
    }
    fn own_entries(&mut self, s: &SyncId) -> Result<Vec<BlobId>> {
        Ok(self.own.get(s).cloned().unwrap_or_default())
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.shredded.push(*s);
        self.paths.remove(s);
        Ok(())
    }
    fn drop_sync_record(&mut self, t: &Tid) -> Result<()> {
        self.dropped.push(*t);
        let mut records = (**self.records.get(&()).unwrap()).clone();
        records.remove(t);
        self.records.insert((), Arc::new(records));
        let mut set = (**self.set.get(&()).unwrap()).clone();
        set.ids.retain(|_, (x, _)| x != t);
        self.set.insert((), Arc::new(set));
        Ok(())
    }
}

#[derive(Default)]
struct Present(StampedSet<(SyncId, BlobId)>);

impl Sources for Present {
    fn present(&self, s: &SyncId, b: &BlobId) -> bool {
        self.0.contains(&(*s, *b))
    }
}

/// A node keeping `n` things unread, thing i under sync ID i, each listed, holding the sync
/// secrets of `held` epochs, head at step 0.
struct Keep {
    g: Fake,
    sources: Present,
    unread: Unread,
}

impl Keep {
    fn new(n: u32, held: &[u64]) -> Keep {
        let mut g = Fake::default();
        let mut set = SyncSet::default();
        let mut records = BTreeMap::new();
        for i in 0..n {
            set.ids.insert(sync_id(i), (thing(i), Holding::Unread));
            records.insert(thing(i), SyncRecord { sync_ids: vec![sync_id(i)], secrets: held.iter().map(|e| (epoch(*e), sync_secret(*e))).collect() });
            g.paths.insert(sync_id(i), Arc::new(Path { steps: vec![(step(sync_id(i), 0), None)] }));
        }
        g.set.insert((), Arc::new(set));
        g.records.insert((), Arc::new(records));
        let mut k = Keep { g, sources: Present::default(), unread: Unread::default() };
        k.settle();
        k
    }

    fn settle(&mut self) -> bool {
        let mut acted = false;
        // as the driver does: again while it acted (a dropped record moves the sync set)
        while self.unread.settle(&mut self.g, &self.sources).unwrap() {
            acted = true;
        }
        acted
    }

    /// A Register moves S's head to step `e`.
    fn register(&mut self, s: SyncId, e: u64) {
        let mut p = (**self.g.paths.get(&s).unwrap()).clone();
        p.steps.push((step(s, e), None));
        self.g.paths.insert(s, Arc::new(p));
        self.settle();
    }

    /// A box of epoch `e`'s sync secret opens.
    fn boxed(&mut self, t: Tid, e: u64) {
        let mut records = (**self.g.records.get(&()).unwrap()).clone();
        records.get_mut(&t).unwrap().secrets.insert(epoch(e), sync_secret(e));
        self.g.records.insert((), Arc::new(records));
        self.settle();
    }

    fn notify(&mut self, n: RemovalNotice) {
        let mut v = self.g.notices.get(&()).map(|n| (**n).clone()).unwrap_or_default();
        v.push(n);
        self.g.notices.insert((), Arc::new(v));
        self.settle();
    }

    fn unlist(&mut self, s: SyncId) {
        let mut set = (**self.g.set.get(&()).unwrap()).clone();
        set.ids.remove(&s);
        self.g.set.insert((), Arc::new(set));
        self.settle();
    }

    fn opens(&self, s: SyncId) -> bool {
        self.unread.credentials(&s).is_some()
    }

    fn stopped(&self, s: SyncId) -> bool {
        self.g.shredded.contains(&s)
    }
}

// spec/sync-judgement.md §6 (keeps): S stays while its synced group's closure lists the thing and
// a sync secret is held; it opens with its head's sync key, the sync proof of it and the head's
// deposit key.
#[test]
fn keeps_and_opens_by_head_spec_sync_judgement_6() {
    let k = Keep::new(1, &[0]);
    let c = k.unread.credentials(&sync_id(0)).expect("opens at its head");
    assert_eq!(c.sync.verifying_key(), step(sync_id(0), 0).keys.sync);
    assert_eq!(c.deposit, step(sync_id(0), 0).keys.deposit);
    assert_eq!(c.proof, Secret32::from_bytes(osis_crypto::kdf::sync_proof(&osis_crypto::label_role_seed(LabelRole::Sync, &sync_secret(0)))));
    assert!(!k.unread.stranded(&sync_id(0)) && k.unread.keeps(&sync_id(0)));
    assert!(k.g.shredded.is_empty());
}

// spec/sync-judgement.md §6 (stranded): a head moved to a step whose sync key no held secret
// derives strands S: it keeps its store, and a box of the new secret ends it. NetKeep `KN_drop`
// (a head move drops the store) fails this.
#[test]
fn head_move_strands_and_keeps_store_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    k.register(sync_id(0), 1);
    assert!(k.unread.stranded(&sync_id(0)));
    assert!(k.g.shredded.is_empty() && k.g.dropped.is_empty(), "nothing dropped on a head move");
    assert!(k.unread.keeps(&sync_id(0)));
    k.boxed(thing(0), 1);
    assert!(!k.unread.stranded(&sync_id(0)));
    assert_eq!(k.unread.credentials(&sync_id(0)).unwrap().sync.verifying_key(), step(sync_id(0), 1).keys.sync);
}

// spec/sync-opens.md §4 (keeping S unread shows its head's sync key): stranded, S opens by no
// older secret it holds. NetKeep `KN_open` (opens by any held secret) fails this.
#[test]
fn stranded_opens_by_no_older_key_spec_sync_opens_4() {
    let mut k = Keep::new(1, &[0]);
    assert!(k.opens(sync_id(0)));
    k.register(sync_id(0), 1);
    assert!(!k.opens(sync_id(0)), "epoch 0's secret is held, but the head is step 1's");
}

// spec/sync-judgement.md §6 (stops): a notice signed by no delete key of the path changes
// nothing; a genuine one stops S at once, shredding it and dropping the record. NetKeep `KN_sig`
// (the signature unchecked) fails this.
#[test]
fn forged_removal_changes_nothing_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    k.notify(notice(sync_id(0), &label_role_key(LabelRole::Delete, &secret(0xf0, 0)), 0));
    let other = notice(sync_id(0), &delete_key(0), 0);
    let sig = sign_removal(&delete_key(0), &sync_id(0), &Tid::from_bytes([8; 15]), &other.commit, 0);
    k.notify(RemovalNotice { sig, ..other.clone() });
    let sig = sign_removal(&delete_key(0), &sync_id(1), &ME, &other.commit, 0);
    k.notify(RemovalNotice { sig, ..other.clone() });
    let sig = sign_removal(&delete_key(0), &sync_id(0), &ME, &other.commit, 1);
    k.notify(RemovalNotice { sig, ..other });
    assert!(!k.stopped(sync_id(0)) && k.opens(sync_id(0)), "forged, or signed over another recipient, sync ID or epoch");
    k.notify(notice(sync_id(0), &delete_key(0), 0));
    assert!(k.stopped(sync_id(0)) && !k.unread.keeps(&sync_id(0)));
    assert_eq!(k.g.dropped, [thing(0)]);
}

// spec/sync-judgement.md §6 (stops): a removal signed at the step before the removing rotation
// still stops a node whose head a Register moved past it before the notice arrived (stranded at
// the new step). NetKeep `KF_late` (verifying under the head's delete key only) fails this.
#[test]
fn removal_signed_before_a_late_head_move_stops_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    k.register(sync_id(0), 1);
    assert!(k.unread.stranded(&sync_id(0)));
    k.notify(notice(sync_id(0), &delete_key(0), 0));
    assert!(k.stopped(sync_id(0)));
}

// spec/sync-judgement.md §6 (stops): a notice that does not verify yet is judged again at each
// head move while held: one signed by the removing rotation's own step stops the node once that
// step is registered.
#[test]
fn held_removal_judged_again_at_head_move_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    k.notify(notice(sync_id(0), &delete_key(1), 0));
    assert!(!k.stopped(sync_id(0)), "step 1 not registered yet");
    k.register(sync_id(0), 1);
    assert!(k.stopped(sync_id(0)));
}

// spec/sync-judgement.md §6 (stops): the path checked runs from the newest step whose sync secret
// is held: a notice signed by an older step's delete key does not stop a node holding a newer
// step's secret.
#[test]
fn removal_below_newest_held_step_ignored_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0, 1]);
    k.register(sync_id(0), 1);
    assert!(!k.unread.stranded(&sync_id(0)));
    k.notify(notice(sync_id(0), &delete_key(0), 1));
    assert!(!k.stopped(sync_id(0)) && k.opens(sync_id(0)));
}

// spec/sync-judgement.md §6 (stops): a notice binding a sync epoch older than one held is stale: K
// removed at epoch 0 (the rotation to step 1 leaving it out) and re-granted at epoch 1 keeps S
// when the removal's notice arrives after the re-grant's box, before or after step 1 is
// registered; a removal of the re-grant stops it. NetKeep `KF_regrant` (no epoch bound) fails
// this.
#[test]
fn removal_notice_stale_after_regrant_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    k.boxed(thing(0), 1);
    k.notify(notice(sync_id(0), &delete_key(0), 0));
    assert!(!k.stopped(sync_id(0)) && k.g.dropped.is_empty(), "the re-grant's box came first");
    k.register(sync_id(0), 1);
    assert!(!k.stopped(sync_id(0)) && k.opens(sync_id(0)));
    k.notify(notice(sync_id(0), &delete_key(1), 1));
    assert!(k.stopped(sync_id(0)), "removed from the re-grant");
}

// spec/sync-judgement.md §6 (stops): a node that stopped on its removal and is re-granted later
// keeps S again although the old notice is still in its inbox, even before any step of its new
// secret is registered. NetKeep `KF_regrant` fails this.
#[test]
fn removal_notice_stale_after_stop_and_regrant_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    k.notify(notice(sync_id(0), &delete_key(0), 0));
    assert!(k.stopped(sync_id(0)));
    let (s, t) = (sync_id(0), thing(0));
    let mut records = (**k.g.records.get(&()).unwrap()).clone();
    records.insert(t, SyncRecord { sync_ids: vec![s], secrets: [(epoch(1), sync_secret(1))].into() });
    k.g.records.insert((), Arc::new(records));
    let mut set = (**k.g.set.get(&()).unwrap()).clone();
    set.ids.insert(s, (t, Holding::Unread));
    k.g.set.insert((), Arc::new(set));
    k.g.paths.insert(s, Arc::new(Path { steps: vec![(step(s, 0), None)] }));
    k.g.shredded.clear();
    k.settle();
    assert!(k.unread.keeps(&s) && k.unread.stranded(&s) && !k.stopped(s), "re-granted, old notice held");
    k.register(s, 1);
    assert!(k.opens(s));
}

// spec/sync-judgement.md §6 (stops): holding the sync secret of no step on its path, a node takes
// a removal signed by its head's delete key only, not an older step's (which may be a removed
// admin's).
#[test]
fn removal_with_no_held_step_checks_head_only_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[2]);
    k.register(sync_id(0), 1);
    assert!(k.unread.stranded(&sync_id(0)));
    k.notify(notice(sync_id(0), &delete_key(0), 2));
    assert!(!k.stopped(sync_id(0)), "step 0 is below the head");
    k.notify(notice(sync_id(0), &delete_key(1), 2));
    assert!(k.stopped(sync_id(0)));
}

// spec/sync-set.md §3 (leaving): unlisted, a node keeping S unread stays (and keeps serving)
// until each entry it logged itself is present at a source, then shreds S and keeps its record;
// one that logged nothing leaves at once. Presence here is a fake `Sources`; the real one is
// streams' (`impl Sources for Streams` answers false until streams builds `known`), which must
// make this hold on a real source (issues/sync-rewrite.md Phase 4).
#[test]
fn leaves_once_own_entries_held_at_a_source_spec_sync_set_3() {
    let mut k = Keep::new(2, &[0]);
    let b = BlobId([0xb1; 32]);
    k.g.own.insert(sync_id(0), vec![b]);
    k.unlist(sync_id(0));
    k.unlist(sync_id(1));
    assert!(k.stopped(sync_id(1)), "nothing of its own: at once");
    assert!(!k.stopped(sync_id(0)) && k.opens(sync_id(0)), "its deposit not yet at a source");
    k.sources.0.insert((sync_id(0), b));
    k.settle();
    assert!(k.stopped(sync_id(0)) && !k.unread.keeps(&sync_id(0)));
    assert!(k.g.dropped.is_empty(), "leaving keeps the record");
}

// spec/sync-judgement.md §6 (read and unread move): raised to read, S is no longer kept unread
// and nothing is shredded.
#[test]
fn raised_to_read_shreds_nothing_spec_sync_judgement_6() {
    let mut k = Keep::new(1, &[0]);
    let mut set = (**k.g.set.get(&()).unwrap()).clone();
    set.ids.insert(sync_id(0), (thing(0), Holding::Read));
    k.g.set.insert((), Arc::new(set));
    k.settle();
    assert!(!k.unread.keeps(&sync_id(0)) && k.g.shredded.is_empty());
}

/// The judgements, removal verifies and mirrored keys one change costs.
fn cost(n: u32, change: impl FnOnce(&mut Keep)) -> [u64; 3] {
    let mut k = Keep::new(n, &[0]);
    osis_base::costs::take();
    change(&mut k);
    let c = osis_base::costs::take();
    let get = |name| c.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
    [get("unread: judged"), get("unread: verifies"), get("unread: mirrored")]
}

// spec/sync-judgement.md §6 (keeps): unread's work follows changes, never every kept sync ID: a
// head move, a box and a removal notice each judge their own S only, at n and 10n kept.
#[test]
fn work_follows_change_spec_sync_judgement_6() {
    for (name, f) in [
        ("head move", (|k: &mut Keep| k.register(sync_id(3), 1)) as fn(&mut Keep)),
        ("box", |k: &mut Keep| k.boxed(thing(3), 1)),
        ("notice", |k: &mut Keep| k.notify(notice(sync_id(3), &delete_key(0), 0))),
        ("idle", |k: &mut Keep| {
            k.settle();
        }),
    ] {
        let (few, many) = (cost(20, f), cost(200, f));
        assert_eq!(few, many, "{name}: [judged, verifies, mirrored] at n and 10n");
        assert!(few[0] <= 2 && (few[0] >= 1) == (name != "idle"), "{name}: {few:?}");
    }
}
