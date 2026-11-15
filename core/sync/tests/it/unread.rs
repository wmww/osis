//! Kept unread (spec/sync-judgement.md §6): the judgement of one S over
//! plain values (`unread::judge`), as the module reads them from the engine facade and the store.
//! Each negative control of core/test/tla/net/NetKeep.tla has a test here that fails without its
//! rule. The module over a real engine (following the sync set) is tests/it/keep.rs; the store's
//! side of a head past its keys (its copy dropped, nothing taken) is tests/it/store.rs.

use osis_base::{SyncId, Tid};
use std::sync::Arc;
use osis_crypto::{Epoch, RoleKey, Secret32, Signature, SigningSecret, role_key};
use osis_engine::sync::{Path, SyncRecord};
use osis_blob::{Step, StepKeys};
use osis_sync::unread::{Judged, judge};


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
    role_key(RoleKey::Delete, &secret(0xad, e))
}

/// Step `e` of `s`: epoch `e`'s sync and delete keys (unread checks no step signature: the store
/// verified the path when it took each Register).
fn step(s: SyncId, e: u64) -> Step {
    let other = role_key(RoleKey::Write, &secret(0x77, e)).verifying_key();
    Step {
        sync_id: s,
        prev: None,
        keys: StepKeys { sync: role_key(RoleKey::Sync, &sync_secret(e)).verifying_key(), write: other, delete: delete_key(e).verifying_key(), deposit: other },
        step_key: [e as u8; 32],
        claims_hash: [0; 32],
        sig: Signature([0; 64]),
    }
}

/// One S kept unread: its record's sync epochs and its registered path's steps.
#[derive(Clone)]
struct Keep {
    s: SyncId,
    held: Vec<u64>,
    /// The epochs of `held` the account's record holds (the rest from boxes payloads held).
    recorded: Vec<u64>,
    /// Whether the record ties S to its thing.
    tied: bool,
    path: Path,
}

/// The thing a `Keep` keeps S for.
fn thing() -> Tid {
    Tid::from_bytes([7; 15])
}

/// A record keeping `s` holding the sync secrets of `held` epochs (all recorded), tied or not.
fn record(s: SyncId, held: &[u64], tied: bool) -> Arc<SyncRecord> {
    let secrets = held.iter().map(|e| (epoch(*e), sync_secret(*e))).collect();
    Arc::new(SyncRecord { sync_ids: vec![s], tied: if tied { [s].into() } else { Default::default() }, secrets, recorded: held.iter().map(|e| epoch(*e)).collect(), dials: Vec::new() })
}

impl Keep {
    /// Holding the sync secrets of `held` epochs, its head at step 0.
    fn new(held: &[u64]) -> Keep {
        let s = sync_id(0);
        Keep { s, held: held.to_vec(), recorded: held.to_vec(), tied: true, path: Path { steps: vec![(step(s, 0), None)] } }
    }

    fn kept(&self) -> osis_sync::unread::Kept {
        let mut r = (*record(self.s, &self.held, self.tied)).clone();
        r.recorded = self.recorded.iter().map(|e| epoch(*e)).collect();
        judge(&Judged { s: self.s, records: &[(thing(), Arc::new(r))], steps: &self.path.steps })
    }

    /// A Register moves S's head to step `e`.
    fn register(&mut self, e: u64) {
        self.path.steps.push((step(self.s, e), None));
    }

    fn opens(&self) -> bool {
        self.kept().credentials.is_some()
    }

    fn stranded(&self) -> bool {
        self.kept().stranded
    }

    /// The sync keys it shows.
    fn shows(&self) -> Vec<osis_crypto::VerifyingKey> {
        self.kept().credentials.map(|c| sync_keys(&c)).unwrap_or_default()
    }
}

// spec/sync-judgement.md §6 (keeps): S stays while its synced group's closure lists the thing and
// a sync secret is held; it opens with its head's sync key, the sync proof of it and the head's
// deposit key.
#[test]
fn keeps_and_opens_by_head_spec_sync_judgement_6() {
    let k = Keep::new(&[0]);
    let c = k.kept().credentials.expect("opens at its head");
    assert_eq!(sync_keys(&c), vec![step(sync_id(0), 0).keys.sync]);
    assert_eq!(c.deposit, Some(step(sync_id(0), 0).keys.deposit));
    assert_eq!(c.keys[0].1, Secret32::from_bytes(osis_crypto::kdf::sync_proof(&osis_crypto::role_key_seed(RoleKey::Sync, &sync_secret(0)))));
    assert!(!k.stranded());
}

// spec/sync-judgement.md §6 (stops), spec/sync-opens.md §4 (keeping S unread): a head moved to a
// step whose sync key no held secret derives stops it (it holds and takes nothing there:
// `stranded`, which the store obeys) and it shows no older key; a box of the head's secret
// (a late box, or a re-grant at that epoch) keeps it again at the head. NetKeep `KN_keep` (keeps
// the store at such a head) and `KN_open` (opens by any held secret) fail this.
#[test]
fn a_head_past_its_keys_stops_until_its_box_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    assert!(k.opens());
    k.register(1);
    assert!(k.stranded(), "stopped: its copy goes");
    assert!(!k.opens(), "epoch 0's secret is held, but step 0 bears it: removed, it shows nothing");
    k.held.push(1);
    assert!(!k.stranded());
    assert_eq!(k.shows(), vec![step(sync_id(0), 1).keys.sync]);
}

// spec/sync-judgement.md §6 (Closes), spec/wire.md §8: a head moved to a closing step drops its
// copy (stranded), shows nothing, and is closed: the account's record keeps S no more.
#[test]
fn a_closing_head_closes_spec_sync_judgement_6() {
    let mut k = Keep::new(&[0]);
    assert!(!k.kept().closed);
    let closing = k.path.steps[0].0.closing(&delete_key(0));
    k.path.steps.push((closing, None));
    let kept = k.kept();
    assert!(kept.closed && kept.stranded, "a closing head keeps S");
    assert!(kept.credentials.is_none(), "a closed S shows its head's key");
}

fn sync_keys(c: &osis_sync::unread::UnreadCredentials) -> Vec<osis_crypto::VerifyingKey> {
    c.keys.iter().map(|(k, _)| k.verifying_key()).collect()
}

// spec/sync-opens.md §4 (keeping S unread: with no head, each sync secret it holds is its step),
// spec/sync-hostile.md (a box at a self-made epoch blocks no other open): before any step is
// registered S opens by the sync key and proof of every sync secret held, newest first, at no
// step, with no deposit key or claim set, so a newer box (here epoch 1, as a hostile one claiming
// a future epoch would be) hides not the grant's (epoch 0); the first step registered moves it
// to the head alone.
#[test]
fn no_head_opens_by_every_sync_secret_spec_sync_opens_4() {
    let mut k = Keep::new(&[0, 1]);
    k.path.steps.clear();
    let c = k.kept().credentials.expect("opens with no head");
    assert_eq!((c.step, c.deposit), (None, None));
    assert_eq!(sync_keys(&c), vec![step(sync_id(0), 1).keys.sync, step(sync_id(0), 0).keys.sync]);
    assert!(!k.stranded());
    k.held.clear();
    assert!(!k.opens(), "no sync secret: nothing");
    k.held.push(1);
    k.register(0);
    k.held.push(0);
    assert_eq!(k.shows(), vec![step(sync_id(0), 0).keys.sync], "at the head alone");
}

// spec/sync-opens.md §4 (keeping S unread: at a head past its keys, the secrets no step of its
// path bears), spec/sync-judgement.md §6 (stops): removed at step 1, then
// re-granted after a further rotation (epoch 2, whose step is not registered here yet), it shows
// epoch 2's key alone, at no step, taking nothing, so a reader holding it registers step 2; there
// it keeps S again. NetKeep `KF_regrant` (showing nothing past its head) fails this.
#[test]
fn a_regrant_past_its_head_shows_the_new_key_spec_sync_opens_4() {
    let mut k = Keep::new(&[0]);
    k.register(1);
    assert!(k.shows().is_empty(), "removed: nothing");
    k.held.push(2);
    assert!(k.stranded(), "still past its keys: holds and takes nothing");
    let c = k.kept().credentials.expect("shows the re-grant's key");
    assert_eq!((c.step, c.deposit, sync_keys(&c)), (None, None, vec![step(sync_id(0), 2).keys.sync]));
    k.register(2);
    assert!(!k.stranded());
    assert_eq!(k.shows(), vec![step(sync_id(0), 2).keys.sync]);
}

// spec/sync-opens.md §4, spec/sync-judgement.md §6: a node granted at epoch 2 whose path is
// registered from genesis takes and holds nothing at steps 0 and 1 (its head past no key of its
// own yet), showing its grant's key so the reader registers on; at step 2 it keeps S.
#[test]
fn a_path_registered_from_genesis_takes_nothing_before_its_key_spec_sync_judgement_6() {
    let mut k = Keep::new(&[2]);
    assert!(k.stranded());
    assert_eq!(k.shows(), vec![step(sync_id(0), 2).keys.sync]);
    k.register(1);
    assert!(k.stranded());
    k.register(2);
    assert!(!k.stranded());
}

// spec/sync-hostile.md (a forged box teaches nothing): a box at a self-made epoch neither hides
// the head's key nor keeps a removed node: at its head it shows the head's key alone; past its
// keys it holds and takes nothing, showing only the self-made key, which no reader holds.
// NetKeep `K_fake` checks the same over every order.
#[test]
fn a_box_at_a_self_made_epoch_keeps_nothing_spec_sync_hostile_1() {
    let mut k = Keep::new(&[0, 1_000_000]);
    assert_eq!(k.shows(), vec![step(sync_id(0), 0).keys.sync]);
    k.register(1);
    assert!(k.stranded(), "removed: its copy goes whatever box it holds");
    assert_eq!(k.shows(), vec![role_key(RoleKey::Sync, &sync_secret(1_000_000)).verifying_key()]);
}

/// The sync key of epoch `e`, as bytes.
fn key_bytes(e: u64) -> [u8; 32] {
    role_key(RoleKey::Sync, &sync_secret(e)).verifying_key().to_bytes()
}

// spec/sync.md §3 (A recorded secret: a held secret goes to the account's record once a step on
// the node's own path bears its sync key): a box's secret a step of the path bears is borne; one
// no step bears (a later epoch not registered yet, a self-made one) is not; a recorded one never
// is again. NetTrust `UN_any` (recorded unconfirmed) fails this.
#[test]
fn a_secret_is_recorded_once_its_path_bears_it_spec_sync_3() {
    let mut k = Keep::new(&[0, 1, 9]);
    k.recorded = vec![0];
    assert!(k.kept().borne.is_empty(), "epoch 1 has no step here yet, 9 never will");
    k.register(1);
    assert_eq!(k.kept().borne, [(thing(), [key_bytes(0), key_bytes(1)].into())].into(), "step 1 bears epoch 1");
    k.recorded = vec![0, 1];
    assert!(k.kept().borne.is_empty(), "recorded: nothing more");
    k.tied = false;
    assert_eq!(k.kept().borne, [(thing(), [key_bytes(0), key_bytes(1)].into())].into(), "untied: its path ties it");
}

// spec/sync.md §3 (S's things: those tied to it when any is, else every thing keeping it; Tied: a
// step on the path bearing a held secret's sync key), spec/sync-hostile.md §2: S kept
// for a forger's thing u (its own key, epoch 9) and the genuine t (epoch 0), in either order.
// Untied, S shows both, so the genuine admin finds it; a step bearing t's key ties t alone, after
// which S shows only t's key. A holder of t's secret boxing it as u's ties both. NetTrust
// `UN_untied` (S synced for every thing keeping it) fails this.
#[test]
fn a_sync_id_kept_for_two_things_is_synced_for_the_one_its_path_ties_spec_sync_3() {
    let s = sync_id(0);
    let u = Tid::from_bytes([1; 15]);
    let t = thing();
    let none: [(Step, Option<osis_blob::ClaimSet>); 0] = [];
    let path = [(step(s, 0), None)];
    let (rt, ru) = (record(s, &[0], false), record(s, &[9], false));
    for records in [vec![(u, ru.clone()), (t, rt.clone())], vec![(t, rt), (u, ru)]] {
        let k = judge(&Judged { s, records: &records, steps: &none });
        let mut want = vec![step(s, 9).keys.sync, step(s, 0).keys.sync];
        assert_eq!(k.credentials.map(|c| sync_keys(&c)).unwrap_or_default(), want, "no head: both things' keys");
        let k = judge(&Judged { s, records: &records, steps: &path });
        assert_eq!(k.borne, [(t, [key_bytes(0)].into())].into(), "step 0 ties t alone");
        // t tied (its own write moves the record)
        let tied: Vec<_> = records.iter().map(|(x, r)| (*x, if *x == t { record(s, &[0], true) } else { r.clone() })).collect();
        let k = judge(&Judged { s, records: &tied, steps: &none });
        want.remove(0);
        assert_eq!(k.credentials.map(|c| sync_keys(&c)).unwrap_or_default(), want, "only t's key once t is tied");
        assert!(judge(&Judged { s, records: &tied, steps: &path }).borne.is_empty(), "u stays untied");
    }
    // t's genuine secret boxed as u's: the path bears it for both
    let records = vec![(t, record(s, &[0], false)), (u, record(s, &[0, 9], false))];
    let k = judge(&Judged { s, records: &records, steps: &path });
    assert_eq!(k.borne.keys().copied().collect::<Vec<_>>(), { let mut v = vec![t, u]; v.sort(); v }, "both tied");
    // ... also when t was tied first: a tie is judged for every record keeping S, not only S's things
    let records = vec![(t, record(s, &[0], true)), (u, record(s, &[0, 9], false))];
    assert_eq!(judge(&Judged { s, records: &records, steps: &path }).borne, [(u, [key_bytes(0)].into())].into(), "u tied after t");
}
