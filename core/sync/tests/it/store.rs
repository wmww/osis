//! The store per sync ID alone (osis_sync::store): one test per rule of spec/sync-ids.md §5-§6,
//! spec/sync-inbox.md §3 and spec/sync-streams.md §3 it implements, crash and reopen at every
//! durable write of an operation, and its costs counted at n and 10n.

use osis_base::format::{MAX_DRIFT_MS, ROLE_KEEP_MS, TOMBSTONE_LIFETIME_MS};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_crypto::{DeleteSecret, Epoch, KemSecret, LabelRole, Secret32, SeededRng, SigningSecret, WRAP_LEN, deposit_key, label_role_key};
use osis_engine::sync::{Caps, Holding, SyncSet};
use osis_label::{ClaimSet, Class, DeleteItem, Parent, Prefix, Reader, Step, StepKeys};
use osis_proto::{Code, DepositItem};
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot, NodeEvent, RecordId};
use osis_sync::store::{Cred, Source, Stand};
use osis_sync::types::{ConnId, Entry};
use osis_sync::Store;
use std::collections::BTreeMap;

/// One simulated device: the store reopens over it after a crash.
struct Dev {
    backend: MemoryBackend,
    root: MemoryRoot,
    faults: Faults,
}

impl Dev {
    fn new() -> Dev {
        let faults = Faults::new();
        Dev { backend: MemoryBackend::with_faults(faults.clone()), root: MemoryRoot::with_faults(faults.clone()), faults }
    }
    fn open(&self) -> Store {
        Store::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Box::new(SeededRng::from_u64(7))).unwrap()
    }
}

/// A sync ID's role secrets and the steps issued so far.
struct Sid {
    id: SyncId,
    sync: Secret32,
    write: Secret32,
    admin: Secret32,
    deposit: Secret32,
    steps: Vec<(Step, ClaimSet)>,
}

const THING: Tid = Tid::from_bytes([0x51; 15]);

impl Sid {
    fn new(b: u8) -> Sid {
        let (sync, write, admin, deposit) = (Secret32::from_bytes([b; 32]), Secret32::from_bytes([b + 1; 32]), Secret32::from_bytes([b + 2; 32]), Secret32::from_bytes([b + 3; 32]));
        let id = osis_label::genesis_label(&admin);
        let mut s = Sid { id, sync, write, admin, deposit, steps: Vec::new() };
        let g = s.issue(&[]);
        s.steps.push(g);
        s
    }
    fn keys(&self) -> StepKeys {
        StepKeys::derive(&self.sync, &self.write, &self.admin, &self.deposit, &self.id)
    }
    fn delete(&self) -> SigningSecret {
        label_role_key(LabelRole::Delete, &self.admin)
    }
    fn write_key(&self) -> SigningSecret {
        label_role_key(LabelRole::Write, &self.write)
    }
    fn sync_key(&self) -> SigningSecret {
        label_role_key(LabelRole::Sync, &self.sync)
    }
    /// The next step (a child of the last), listing `readers`.
    fn issue(&self, readers: &[Reader]) -> (Step, ClaimSet) {
        let mut rng = SeededRng::from_u64(self.steps.len() as u64 + 99);
        let n = self.steps.len() as u64;
        let read = Epoch::derive(&THING, osis_base::Role::Read, n, &self.write).unwrap();
        let sync = Epoch::derive(&THING, osis_base::Role::Sync, n, &self.sync).unwrap();
        let d = self.delete();
        let parent = match self.steps.last() {
            None => Parent::Genesis(&d),
            Some((p, _)) => Parent::Child { step: p, delete: &d },
        };
        osis_label::register(parent, self.keys(), readers, (&THING, read, &self.write), (sync, &self.sync), &mut rng).unwrap()
    }
    /// Rotates the write and sync secrets and issues the next step.
    fn rotate(&mut self, b: u8) -> (Step, ClaimSet) {
        self.write = Secret32::from_bytes([b; 32]);
        self.sync = Secret32::from_bytes([b + 1; 32]);
        let st = self.issue(&[]);
        self.steps.push(st.clone());
        st
    }
    fn head(&self) -> &Step {
        &self.steps.last().unwrap().0
    }
}

fn holding(sids: &[(&Sid, Holding)]) -> SyncSet {
    SyncSet { ids: sids.iter().map(|(s, h)| (s.id, (THING, *h))).collect(), ..SyncSet::default() }
}

/// A store holding `s` kept unread, its genesis registered.
fn unread(dev: &Dev, s: &Sid) -> Store {
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(s, Holding::Unread)]));
    let (g, c) = &s.steps[0];
    assert_eq!(st.take_register(&s.id, g, Some(c)).unwrap(), Code::OK);
    st
}

/// A blob of `class` with `n` bytes of payload, `expiry`, and delete-key commitments `keys`.
fn blob(n: usize, class: Class, expiry: Option<u64>, keys: &[(u8, osis_crypto::VerifyingKey)]) -> (BlobId, Vec<u8>) {
    let mut rng = SeededRng::from_u64(n as u64 ^ 0x5eed ^ expiry.unwrap_or(0));
    let p = Prefix::for_keys([n as u8; 16], &[1; 16], expiry.map(WallMs), keys).unwrap().with_class(class);
    let (_, bytes) = osis_label::frame(&p, &vec![n as u8; n], &mut rng).unwrap();
    (osis_label::blob_id(&bytes), bytes)
}

fn wrap(n: u8) -> [u8; WRAP_LEN] {
    [n; WRAP_LEN]
}

/// A stamped entry of `b` under `s`'s current write key.
fn stamped(s: &Sid, b: BlobId, role: bool) -> Entry {
    let w = wrap(1);
    let stamp = osis_label::sign_stamp(&s.write_key(), &s.id, &b, &w, role);
    Entry { blob: b, wrap: w, stamp: Some(stamp), deposited: false, own: false, role, class: Class::Durable, expires: None }
}

fn deposit(s: &Sid, bytes: &[u8], role: bool) -> DepositItem {
    let b = osis_label::blob_id(bytes);
    let w = wrap(2);
    let sig = osis_label::sign_deposit(&deposit_key(&s.deposit, &s.id), &s.id, &b, &w, role);
    DepositItem { sync_id: s.id, blob: bytes.to_vec(), wrap: w, sig }
}

fn events_of(st: &Store, s: &SyncId) -> Vec<NodeEvent> {
    st.read_sync(s, None, None, usize::MAX - 1).unwrap().events.into_iter().map(|e| e.event).collect()
}

// spec/sync-ids.md §6 (register), spec/wire.md §11.2 (Register): a genesis step is taken only
// into an empty path and only if it verifies (else 1; a child into an empty path 13); then only a
// child of the head (9 else), the head itself answered 0 with nothing changed; a step of another
// sync ID is 2; a taken step moves the head (a head event in the log).
#[test]
fn register_takes_genesis_then_children_of_the_head_spec_sync_ids_6() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
    let (c1, cs1) = s.rotate(60);
    assert_eq!(st.take_register(&s.id, &c1, Some(&cs1)).unwrap(), Code::UNKNOWN_SYNC_ID, "a child into an empty path");
    let mut forged = s.steps[0].0.clone();
    forged.sig = c1.sig;
    assert_eq!(st.take_register(&s.id, &forged, None).unwrap(), Code::REFUSED, "a genesis that does not verify");
    let (g, gc) = s.steps[0].clone();
    assert_eq!(st.take_register(&s.id, &g, Some(&gc)).unwrap(), Code::OK);
    assert_eq!(st.take_register(&s.id, &g, None).unwrap(), Code::OK, "the head again");
    let other = Sid::new(40);
    assert_eq!(st.take_register(&s.id, &other.steps[0].0, None).unwrap(), Code::MALFORMED, "another sync ID's step");
    let (c2, cs2) = s.rotate(70);
    assert_eq!(st.take_register(&s.id, &c2, Some(&cs2)).unwrap(), Code::NOT_HEAD_KEY, "a step whose prev is not the head");
    assert_eq!(st.take_register(&s.id, &c1, Some(&cs1)).unwrap(), Code::OK);
    assert_eq!(st.take_register(&s.id, &g, None).unwrap(), Code::NOT_HEAD_KEY, "a genesis past the empty path");
    assert_eq!(st.take_register(&s.id, &c2, Some(&cs2)).unwrap(), Code::OK);
    assert_eq!(st.head(&s.id).unwrap().as_ref(), Some(&c2));
    assert_eq!(st.path(&s.id).unwrap().unwrap().steps.len(), 3);
    assert_eq!(events_of(&st, &s.id), [NodeEvent::Head(s.id)], "one head event, the latest");
}

// spec/sync-ids.md §6 (claim set hash): a claim set registered with a step must hash to the
// step's; one that does not is refused with the step.
#[test]
fn register_refuses_a_claim_set_of_another_hash_spec_sync_ids_6() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (c1, _) = s.rotate(60);
    let (_, wrong) = s.rotate(70);
    assert_eq!(st.take_register(&s.id, &c1, Some(&wrong)).unwrap(), Code::MALFORMED);
    assert_eq!(st.head(&s.id).unwrap().as_ref(), Some(&s.steps[0].0));
}

// spec/sync-ids.md §6 (register only unread): a node reading S refuses every Register of S, as
// does a node not syncing S (14).
#[test]
fn register_only_where_kept_unread_spec_sync_ids_6() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = dev.open();
    assert_eq!(st.take_register(&s.id, &s.steps[0].0, None).unwrap(), Code::DECLINED, "not synced");
    st.set_sync_set(&holding(&[(&s, Holding::Read)]));
    assert_eq!(st.take_register(&s.id, &s.steps[0].0, None).unwrap(), Code::DECLINED, "read");
    assert!(st.head(&s.id).unwrap().is_none());
}

// spec/sync-ids.md §6 (register; storage caps): past the caps a genesis is refused (12), a child
// is taken without its claim set, and past them even without it at most once per interval.
#[test]
fn register_past_the_caps_spec_sync_ids_6() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
    let tiny = |bytes: u64| Caps { policy: BTreeMap::from([("bytes".to_string(), bytes), ("register_every_ms".to_string(), 1000)]), ..Caps::default() };
    st.set_caps(&tiny(10));
    assert_eq!(st.take_register(&s.id, &s.steps[0].0, Some(&s.steps[0].1)).unwrap(), Code::STORAGE_CAP);
    st.set_caps(&tiny(u64::MAX));
    assert_eq!(st.take_register(&s.id, &s.steps[0].0, None).unwrap(), Code::OK);
    // room for one more step (a child is a little longer), not for its claim set too
    let step = st.usage(&s.id).unwrap().0.bytes;
    st.set_caps(&tiny(2 * step + 64));
    let (c1, cs1) = s.rotate(60);
    assert_eq!(st.take_register(&s.id, &c1, Some(&cs1)).unwrap(), Code::OK);
    assert!(st.path(&s.id).unwrap().unwrap().steps[1].1.is_none(), "taken without its claim set");
    let (c2, _) = s.rotate(70);
    let (c3, _) = s.rotate(80);
    assert_eq!(st.take_register(&s.id, &c2, None).unwrap(), Code::OK, "past even without it: once");
    assert_eq!(st.take_register(&s.id, &c3, None).unwrap(), Code::STORAGE_CAP, "twice in an interval");
    st.settle_at(WallMs(1000)).unwrap();
    assert_eq!(st.take_register(&s.id, &c3, None).unwrap(), Code::OK, "the next interval");
}

// spec/sync-ids.md §6 (behind): named a step on its path other than its head by a credential of
// that step, a node keeping S unread answers the steps after it through the first under another
// sync key; naming none by a sync key, the step after the newest step bearing it; at most the
// step bound (4 reaching it with none); 13 for a sync ID not kept, 14 anything else.
#[test]
fn behind_answers_up_to_the_next_sync_key_spec_sync_ids_6() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let k0 = s.sync_key().verifying_key();
    let mut st = unread(&dev, &s);
    // a step without rotation keeps the sync key, then a rotation moves it
    let same = s.issue(&[]);
    s.steps.push(same.clone());
    let (c2, cs2) = s.rotate(60);
    let (c3, cs3) = s.rotate(70);
    for (c, cs) in [(&same.0, &same.1), (&c2, &cs2), (&c3, &cs3)] {
        assert_eq!(st.take_register(&s.id, c, Some(cs)).unwrap(), Code::OK);
    }
    let g = s.steps[0].0.id();
    let (code, grant) = st.behind(&s.id, Some(&g), &Cred::Sync(k0), 100).unwrap();
    assert_eq!(code, Code::OK);
    assert_eq!(grant.unwrap().steps, [same.0.clone(), c2.clone()], "through the first under another sync key");
    let (code, grant) = st.behind(&s.id, None, &Cred::Sync(k0), 100).unwrap();
    assert_eq!((code, grant.unwrap().steps), (Code::OK, vec![c2.clone()]), "after the newest bearing the key");
    assert_eq!(st.behind(&s.id, Some(&g), &Cred::Sync(k0), 0).unwrap().0, Code::RATE_LIMITED, "the bound reached with none");
    assert_eq!(st.behind(&s.id, Some(&g), &Cred::Sync(c3.keys.sync), 100).unwrap().0, Code::DECLINED, "not the named step's credential");
    assert_eq!(st.behind(&s.id, Some(&c3.id()), &Cred::Sync(c3.keys.sync), 100).unwrap().0, Code::DECLINED, "the head");
    assert_eq!(st.behind(&SyncId([9; 16]), None, &Cred::Sync(k0), 100).unwrap().0, Code::UNKNOWN_SYNC_ID);
}

// spec/sync-ids.md §6 (behind static): naming no step, by a key actor's signing key whose static
// entry the head's claim set lists, the answer is the head's entry box for it and the path from
// genesis.
#[test]
fn behind_by_a_static_entry_grants_the_path_spec_sync_ids_6() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let link = SigningSecret::from_seed(&Secret32::from_bytes([77; 32]));
    let kem = KemSecret::derive(&Secret32::from_bytes([78; 32]));
    let (c1, cs1) = s.issue(&[Reader::Static { signing: link.verifying_key(), kem: kem.public() }]);
    s.steps.push((c1.clone(), cs1.clone()));
    assert_eq!(st.take_register(&s.id, &c1, Some(&cs1)).unwrap(), Code::OK);
    let (code, grant) = st.behind(&s.id, None, &Cred::Signing(link.verifying_key()), 100).unwrap();
    let grant = grant.unwrap();
    assert_eq!(code, Code::OK);
    assert_eq!(grant.steps, [s.steps[0].0.clone(), c1.clone()]);
    assert_eq!(grant.entry_box.as_ref(), cs1.entry_box(&s.id, &link.verifying_key()));
    let stranger = SigningSecret::from_seed(&Secret32::from_bytes([79; 32]));
    assert_eq!(st.behind(&s.id, None, &Cred::Signing(stranger.verifying_key()), 100).unwrap().0, Code::DECLINED);
    assert_eq!(st.behind(&s.id, None, &Cred::Signing(link.verifying_key()), 1).unwrap().0, Code::RATE_LIMITED, "a grant past the bound");
}

// spec/sync-ids.md §6 (stamp refusals): a node keeping S unread refuses a bad stamp (1), a stamp
// under a superseded write key (9), an expired blob (7), a tombstoned blob ID (6), an oversized
// blob, and takes a good one with wrap and stamp.
#[test]
fn stamped_entries_refused_and_taken_spec_sync_ids_6() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, bytes) = blob(100, Class::Durable, None, &[]);
    let old = stamped(&s, b, false);
    let (c1, cs1) = s.rotate(60);
    assert_eq!(st.take_register(&s.id, &c1, Some(&cs1)).unwrap(), Code::OK);
    assert_eq!(st.take_stamped(&s.id, &old, bytes.clone()).unwrap(), Code::NOT_HEAD_KEY, "superseded write key");
    let mut bad = stamped(&s, b, false);
    bad.wrap = wrap(9);
    assert_eq!(st.take_stamped(&s.id, &bad, bytes.clone()).unwrap(), Code::REFUSED, "bad stamp");
    st.settle_at(WallMs(500)).unwrap();
    let (xb, xbytes) = blob(101, Class::Durable, Some(400), &[]);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, xb, false), xbytes).unwrap(), Code::EXPIRED);
    let mut big = stamped(&s, b, false);
    big.blob = BlobId([1; 32]);
    assert_eq!(st.take_stamped(&s.id, &big, vec![0; osis_base::format::MAX_BLOB + 1]).unwrap(), Code::TOO_LARGE);
    let good = stamped(&s, b, false);
    assert_eq!(st.take_stamped(&s.id, &good, bytes.clone()).unwrap(), Code::OK);
    assert_eq!(st.entry(&s.id, &b).unwrap().unwrap(), good);
    assert_eq!(st.bytes(&b).unwrap().unwrap(), bytes);
    // a Delete tombstones it: taking it again is 6
    let del = DeleteItem::sign(&s.delete(), &s.id, b);
    assert_eq!(st.take_delete(&s.id, &[del], true).unwrap(), [Code::OK]);
    assert_eq!(st.take_stamped(&s.id, &good, bytes).unwrap(), Code::TOMBSTONED);
}

// spec/sync-ids.md §6 (Taking a stamped entry): a stamped entry of a deposited entry's blob ID
// replaces its wrap and stamp and clears the flag; a stamped entry's wrap and stamp never change
// after: taking it again changes nothing and logs no event.
#[test]
fn a_stamp_replaces_a_deposit_once_spec_sync_ids_6() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, bytes) = blob(100, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::OK);
    assert!(st.entry(&s.id, &b).unwrap().unwrap().deposited);
    assert_eq!(st.usage(&s.id).unwrap().0.deposits, 1);
    let e = stamped(&s, b, false);
    assert_eq!(st.take_stamped(&s.id, &e, bytes.clone()).unwrap(), Code::OK);
    assert_eq!(st.entry(&s.id, &b).unwrap().unwrap(), e);
    assert_eq!(st.usage(&s.id).unwrap().0.deposits, 0, "it left the deposit budget");
    let before = st.read_sync(&s.id, None, None, 100).unwrap().events;
    let mut other = e.clone();
    other.wrap = wrap(5);
    other.stamp = Some(osis_label::sign_stamp(&s.write_key(), &s.id, &b, &other.wrap, false));
    assert_eq!(st.take_stamped(&s.id, &other, bytes.clone()).unwrap(), Code::OK);
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::OK, "a deposit of a held blob");
    assert_eq!(st.entry(&s.id, &b).unwrap().unwrap(), e, "wrap and stamp kept");
    assert_eq!(st.read_sync(&s.id, None, None, 100).unwrap().events, before, "no event");
}

// spec/sync-ids.md §6 (role entries; caps at a node keeping S unread): a role entry is taken outside S's caps, stamped with
// no bound of its own, deposited within the deposit budget; other entries past the caps are
// refused for room (12).
#[test]
fn role_entries_pass_the_caps_spec_sync_ids_6() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    st.set_caps(&Caps { policy: BTreeMap::from([("entries".to_string(), 1)]), ..Caps::default() });
    let (b1, x1) = blob(100, Class::Durable, None, &[]);
    let (b2, x2) = blob(101, Class::Durable, None, &[]);
    let (b3, x3) = blob(102, Class::Durable, None, &[]);
    let (b4, x4) = blob(103, Class::Durable, None, &[]);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b1, false), x1).unwrap(), Code::OK);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b2, false), x2).unwrap(), Code::STORAGE_CAP);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b3, true), x3).unwrap(), Code::OK, "a stamped role entry");
    assert_eq!(st.take_deposit(&deposit(&s, &x4, true), None).unwrap(), Code::OK, "a deposited role entry");
    assert_eq!(st.usage(&s.id).unwrap().0.entries, 1, "role entries count toward no cap");
    assert!(st.entry(&s.id, &b4).unwrap().is_some());
}

// spec/sync-inbox.md §3 (deposit refusals): 0 taken (and for a held or dropped blob, changing
// nothing); 4 for a sync ID the node will hold but holds no head of yet; 5 past the budget; 12
// past a cap; 14 for a bad signature, a relay-only blob, an unknown sync ID; never the head.
#[test]
fn deposit_answers_spec_sync_inbox_3() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = dev.open();
    let (b, bytes) = blob(100, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::DECLINED, "not synced");
    st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::RATE_LIMITED, "no head yet");
    let (g, c) = &s.steps[0];
    st.take_register(&s.id, g, Some(c)).unwrap();
    let mut forged = deposit(&s, &bytes, false);
    forged.wrap = wrap(7);
    assert_eq!(st.take_deposit(&forged, None).unwrap(), Code::DECLINED, "bad signature");
    let (_, relay) = blob(50, Class::Relay, Some(10), &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &relay, false), None).unwrap(), Code::DECLINED, "relay-only");
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::OK);
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::OK, "held");
    st.drop_entry(&s.id, &b, Vec::new()).unwrap();
    assert_eq!(st.take_deposit(&deposit(&s, &bytes, false), None).unwrap(), Code::OK, "dropped");
    assert!(st.entry(&s.id, &b).unwrap().is_none(), "nothing changed");
    st.set_caps(&Caps { policy: BTreeMap::from([("entries".to_string(), 0)]), ..Caps::default() });
    let (_, x) = blob(101, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &x, false), None).unwrap(), Code::STORAGE_CAP);
}

// spec/sync-inbox.md §3 (deposit budget): one budget per sync ID for durable and ephemeral
// deposits alike, at least `64 + 4 ×` the head's claim-set size entries; past it, 5. An entry
// leaves the budget when stamped or deleted.
#[test]
fn deposit_budget_spec_sync_inbox_3() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    // the genesis claim set holds one key: 68 entries
    let mut taken = Vec::new();
    for i in 0..68 {
        let class = if i % 2 == 0 { Class::Durable } else { Class::Ephemeral };
        let (b, x) = blob(64 + i, class, Some(10_000_000), &[]);
        assert_eq!(st.take_deposit(&deposit(&s, &x, false), None).unwrap(), Code::OK, "deposit {i}");
        taken.push((b, x));
    }
    let (_, x) = blob(400, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &x, false), None).unwrap(), Code::DEPOSIT_BUDGET_FULL);
    let (b0, x0) = &taken[0];
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, *b0, false), x0.clone()).unwrap(), Code::OK);
    assert_eq!(st.take_deposit(&deposit(&s, &x, false), None).unwrap(), Code::OK, "a stamp freed one");
}

// spec/sync-inbox.md §3 (deposit from anyone): a Deposit item is taken by its signature and the
// budgets alone, whatever the connection proved and whoever offers it: a peer with a record, a
// connection without one, or none.
#[test]
fn deposits_from_anyone_spec_sync_inbox_3() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    for (i, from) in [None, Some(Source::Conn(ConnId(3))), Some(Source::Record([4; 16]))].into_iter().enumerate() {
        let (b, x) = blob(100 + i, Class::Durable, None, &[]);
        assert_eq!(st.take_deposit(&deposit(&s, &x, false), from).unwrap(), Code::OK);
        assert!(st.entry(&s.id, &b).unwrap().unwrap().deposited);
    }
}

// spec/sync-opens.md §3 (a record dropped): drops everything of that peer with it and
// spec/sync-ids.md §5 (Peer budget): a record evicted past `RECORD_BUDGET` takes what was charged
// to it in the same transaction: a failed eviction leaves both, a landed one neither.
#[test]
fn an_evicted_record_takes_its_charges_at_once_spec_sync_opens_3() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let rec = st.with_tx(|t| t.record_create([1; 32], &[])).unwrap();
    let (b, x) = blob(1003, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &x, false), Some(Source::Record(rec))).unwrap(), Code::OK);
    let none = std::collections::BTreeSet::new();
    dev.faults.at(0, Fault::Fail);
    assert!(st.write_records(0, &none, |_| Ok(())).is_err());
    assert!(st.with_read(|t| t.record(&rec)).unwrap().is_some() && st.entry(&s.id, &b).unwrap().is_some(), "a failed eviction leaves both");
    assert_eq!(st.write_records(0, &none, |_| Ok(())).unwrap(), [rec]);
    assert!(st.with_read(|t| t.record(&rec)).unwrap().is_none());
    assert!(st.entry(&s.id, &b).unwrap().is_none(), "what the peer brought went with its record");
}

// spec/sync-ids.md §5 (Peer budget): unstamped entries giving nothing held count against the
// peer that brought them, within a bound; past it they are not kept. A peer with no record is
// charged per connection, and what it brought goes when the connection closes.
#[test]
fn peer_budget_spec_sync_ids_5() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    st.set_caps(&Caps { policy: BTreeMap::from([("peer_bytes".to_string(), 1500)]), ..Caps::default() });
    let c = Source::Conn(ConnId(1));
    let (b1, x1) = blob(1000, Class::Durable, None, &[]);
    let (_, x2) = blob(1001, Class::Durable, None, &[]);
    let (b3, x3) = blob(1002, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &x1, false), Some(c)).unwrap(), Code::OK);
    assert_eq!(st.take_deposit(&deposit(&s, &x2, false), Some(c)).unwrap(), Code::DEPOSIT_BUDGET_FULL);
    assert_eq!(st.take_deposit(&deposit(&s, &x3, false), Some(Source::Conn(ConnId(2)))).unwrap(), Code::OK, "another peer's own bound");
    st.uncharge(&s.id, &b3).unwrap();
    st.gone(Source::Conn(ConnId(1))).unwrap();
    st.gone(Source::Conn(ConnId(2))).unwrap();
    assert!(st.entry(&s.id, &b1).unwrap().is_none(), "what the closed connection brought went");
    assert!(st.entry(&s.id, &b3).unwrap().is_some(), "an entry giving something held stays");
    assert_eq!(st.take_deposit(&deposit(&s, &x2, false), Some(c)).unwrap(), Code::OK, "the charge went with it");
    // a peer's record: its charges outlive its connections and go with the record
    let rec = st.with_tx(|t| t.record_create([1; 32], &[])).unwrap();
    let (b4, x4) = blob(1003, Class::Durable, None, &[]);
    assert_eq!(st.take_deposit(&deposit(&s, &x4, false), Some(Source::Record(rec))).unwrap(), Code::OK);
    st.gone(Source::Conn(ConnId(1))).unwrap();
    assert!(st.entry(&s.id, &b4).unwrap().is_some(), "a record's charge outlives a connection");
    st.gone(Source::Record(rec)).unwrap();
    assert!(st.entry(&s.id, &b4).unwrap().is_none(), "a dropped record is a first contact");
    // a reader's own judgement logging unstamped entries a peer brought: the same bound
    let r = Sid::new(40);
    let mut st = Dev::new().open();
    st.set_sync_set(&holding(&[(&r, Holding::Read)]));
    st.set_caps(&Caps { policy: BTreeMap::from([("peer_bytes".to_string(), 1500)]), ..Caps::default() });
    let unstamped = |b| Entry { blob: b, wrap: wrap(3), stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: None };
    let c = Source::Conn(ConnId(3));
    assert_eq!(st.log(&r.id, unstamped(b1), Some(x1), Some(c)).unwrap(), Code::OK);
    let (b2, x2) = blob(1001, Class::Durable, None, &[]);
    assert_eq!(st.log(&r.id, unstamped(b2), Some(x2.clone()), Some(c)).unwrap(), Code::DEPOSIT_BUDGET_FULL, "past the peer's bound: not kept");
    assert!(st.entry(&r.id, &b2).unwrap().is_none());
    assert_eq!(st.log(&r.id, unstamped(b2), Some(x2), None).unwrap(), Code::OK, "an entry charged to nobody");
}

// spec/sync-ids.md §6 (delete opened): a Delete is taken at a node keeping S unread only on a
// connection where S is open by a store credential, else refused whole (8).
#[test]
fn delete_needs_a_store_credential_spec_sync_ids_6() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, x) = blob(100, Class::Durable, None, &[]);
    st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
    let del = DeleteItem::sign(&s.delete(), &s.id, b);
    assert_eq!(st.take_delete(&s.id, &[del.clone(), del.clone()], false).unwrap(), [Code::NOT_OPEN, Code::NOT_OPEN]);
    assert!(st.entry(&s.id, &b).unwrap().is_some());
    assert_eq!(st.take_delete(&s.id, &[del], true).unwrap(), [Code::OK]);
    assert!(st.entry(&s.id, &b).unwrap().is_none());
    assert!(st.tombstone(&s.id, &b).unwrap().unwrap().deleted);
    assert!(st.bytes(&b).unwrap().is_none(), "its bytes went with the last entry naming them");
}

// spec/wire.md §11.2 (an item whose entry is not held): a Delete of an entry not held changes nothing: by the
// delete key 0 where a tombstone of the blob exists (a repeat), else 1; by levels 1. So a peer
// adds no row for a blob this node does not hold.
#[test]
fn delete_of_an_entry_not_held_changes_nothing_spec_wire_11_2() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, x) = blob(100, Class::Durable, None, &[]);
    let (never, _) = blob(101, Class::Durable, None, &[]);
    st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
    let del = |b| DeleteItem::sign(&s.delete(), &s.id, b);
    let before = st.usage(&s.id).unwrap().0;
    assert_eq!(st.take_delete(&s.id, &[del(never)], true).unwrap(), [Code::REFUSED]);
    assert!(st.tombstone(&s.id, &never).unwrap().is_none(), "no tombstone for a blob never held");
    assert_eq!(st.usage(&s.id).unwrap().0, before);
    assert_eq!(st.take_delete(&s.id, &[del(b), del(b)], true).unwrap(), [Code::OK, Code::OK], "a repeat is idempotent");
    let d2 = DeleteSecret::derive(&Secret32::from_bytes([21; 32]));
    let by = DeleteItem::sign_by(&s.sync_key(), &[(2, &d2)], &[5; 16], &[1; 16], &s.id, b).unwrap();
    assert_eq!(st.take_delete(&s.id, &[by], true).unwrap(), [Code::REFUSED], "by levels: the prefix is gone");
}

// spec/sync-ids.md §6 (Delete): checking a Delete reads the blob's prefix, never its ciphertext:
// the bytes read do not grow with the blob (counted at n and 10n).
#[test]
fn delete_reads_only_the_prefix_spec_sync_ids_6() {
    let read = |n: usize| {
        let dev = Dev::new();
        let s = Sid::new(10);
        let mut st = unread(&dev, &s);
        let (b, x) = blob(n, Class::Durable, None, &[]);
        st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
        osis_base::costs::take();
        assert_eq!(st.take_delete(&s.id, &[DeleteItem::sign(&s.delete(), &s.id, b)], true).unwrap(), [Code::OK]);
        osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "store blob bytes read").map(|(.., n)| n).sum::<u64>()
    };
    let (a, b) = (read(10_000), read(100_000));
    assert!(a > 0 && a <= 256);
    assert_eq!(a, b, "bytes read: {a} for a blob of n, {b} for 10n");
}

// spec/sync-ids.md §6 (delete keys): a Delete by levels needs one delete signature per
// commitment group of the blob's prefix, each under that group's commitment, with the head's
// write key when any level is 3, else its sync key; anything else is refused.
#[test]
fn delete_by_levels_spec_sync_ids_6() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let d2 = DeleteSecret::derive(&Secret32::from_bytes([21; 32]));
    let d3 = DeleteSecret::derive(&Secret32::from_bytes([22; 32]));
    let p = Prefix::for_keys([5; 16], &[1; 16], None, &[(2, d2.verifying_key())]).unwrap();
    let mut rng = SeededRng::from_u64(3);
    let (_, bytes) = osis_label::frame(&p, b"body", &mut rng).unwrap();
    let b = osis_label::blob_id(&bytes);
    st.take_stamped(&s.id, &stamped(&s, b, false), bytes).unwrap();
    let by = |key: &SigningSecret, dks: &[(u8, &DeleteSecret)]| DeleteItem::sign_by(key, dks, &[5; 16], &[1; 16], &s.id, b).unwrap();
    assert_eq!(st.take_delete(&s.id, &[by(&s.sync_key(), &[(2, &d3)])], true).unwrap(), [Code::REFUSED], "a key the prefix does not commit to");
    assert_eq!(st.take_delete(&s.id, &[by(&s.write_key(), &[(2, &d2)])], true).unwrap(), [Code::REFUSED], "level 2 with the write key");
    assert!(st.entry(&s.id, &b).unwrap().is_some());
    assert_eq!(st.take_delete(&s.id, &[by(&s.sync_key(), &[(2, &d2)])], true).unwrap(), [Code::OK]);
    assert!(st.entry(&s.id, &b).unwrap().is_none());
}

// spec/sync-ids.md §6 (Expiry): at the prefix's expiry every node deletes the entry outright: no
// tombstone, and no event in the log (spec/wire.md §11.2: expiry produces no event).
#[test]
fn expiry_leaves_no_tombstone_spec_sync_ids_6() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, x) = blob(100, Class::Durable, Some(1000), &[]);
    st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
    assert_eq!(st.next_wake(), Some(WallMs(1000)));
    st.settle_at(WallMs(1000)).unwrap();
    assert!(st.entry(&s.id, &b).unwrap().is_none());
    assert!(st.tombstone(&s.id, &b).unwrap().is_none());
    assert!(st.bytes(&b).unwrap().is_none());
    assert_eq!(events_of(&st, &s.id), [NodeEvent::Head(s.id)]);
}

// spec/sync-ids.md §5 (Tombstones): a tombstone is kept `TOMBSTONE_LIFETIME`, then the blob ID may
// come back.
#[test]
fn tombstones_end_after_their_lifetime_spec_sync_ids_5() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, x) = blob(100, Class::Durable, None, &[]);
    let e = stamped(&s, b, false);
    st.take_stamped(&s.id, &e, x.clone()).unwrap();
    st.take_delete(&s.id, &[DeleteItem::sign(&s.delete(), &s.id, b)], true).unwrap();
    st.settle_at(WallMs(TOMBSTONE_LIFETIME_MS - 1)).unwrap();
    assert_eq!(st.take_stamped(&s.id, &e, x.clone()).unwrap(), Code::TOMBSTONED);
    st.settle_at(WallMs(TOMBSTONE_LIFETIME_MS)).unwrap();
    assert_eq!(st.take_stamped(&s.id, &e, x).unwrap(), Code::OK);
}

// spec/sync-ids.md §5 (Across sync IDs): blob bytes are stored once per node and deleted when no
// sync ID references them (nor the engine); a blob fetched under one sync ID is taken under every
// other held sync ID whose entries name it.
#[test]
fn bytes_once_per_node_spec_sync_ids_5() {
    let dev = Dev::new();
    let (s1, s2) = (Sid::new(10), Sid::new(40));
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s1, Holding::Read), (&s2, Holding::Read)]));
    let (b, x) = blob(100, Class::Durable, None, &[]);
    let e = Entry { blob: b, wrap: wrap(1), stamp: None, deposited: false, own: true, role: false, class: Class::Durable, expires: None };
    assert_eq!(st.log(&s2.id, e.clone(), None, None).unwrap(), Code::OK);
    assert!(events_of(&st, &s2.id).is_empty(), "no bytes: not servable");
    assert_eq!(st.log(&s1.id, e.clone(), Some(x.clone()), None).unwrap(), Code::OK);
    assert_eq!(events_of(&st, &s2.id), [NodeEvent::Added(s2.id, b)], "taken under the other sync ID naming it");
    st.drop_entry(&s1.id, &b, Vec::new()).unwrap();
    assert_eq!(st.bytes(&b).unwrap().unwrap(), x, "still named under s2");
    // the engine holds it too
    let door = st.cipher();
    {
        let mut tx = door.begin();
        tx.hold(&b, x.clone(), false).unwrap();
        tx.commit().unwrap();
    }
    st.drop_entry(&s2.id, &b, Vec::new()).unwrap();
    assert!(st.bytes(&b).unwrap().is_some(), "the engine still holds it");
    {
        let mut tx = door.begin();
        tx.release(&b, false).unwrap();
        tx.commit().unwrap();
    }
    assert!(st.bytes(&b).unwrap().is_none());
}

// spec/sync-ids.md §5 (Across sync IDs): ephemeral entries and their tombstones are held in memory
// only and lost at a restart; relay-only blobs are never held. Ephemeral tombstones last
// `MAX_DRIFT`.
#[test]
fn ephemeral_entries_live_in_memory_spec_sync_ids_5() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, x) = blob(100, Class::Ephemeral, Some(10 * MAX_DRIFT_MS), &[]);
    dev.faults.forbid_writes(true);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b, false), x.clone()).unwrap(), Code::OK);
    assert_eq!(dev.faults.forbidden(), 0, "no durable write");
    dev.faults.forbid_writes(false);
    assert_eq!(st.read_memory(&s.id, 0, 10).0.len(), 1);
    assert!(st.read_sync(&s.id, None, None, 10).unwrap().events.iter().all(|e| !matches!(e.event, NodeEvent::Added(..))), "no position names it");
    st.drop_entry(&s.id, &b, Vec::new()).unwrap();
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b, false), x.clone()).unwrap(), Code::TOMBSTONED);
    st.settle_at(WallMs(MAX_DRIFT_MS)).unwrap();
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap(), Code::OK, "its tombstone lasted MAX_DRIFT");
    drop(st);
    let st = dev.open();
    assert!(st.entry(&s.id, &b).unwrap().is_none() && st.bytes(&b).unwrap().is_none(), "lost at a restart");
    let (r, rx) = blob(60, Class::Relay, Some(10), &[]);
    let mut st = unread(&Dev::new(), &s);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, r, false), rx).unwrap(), Code::DECLINED, "relay-only is never held");
}

// spec/sync-ids.md §5 (Caps), §6 (Caps at a node keeping S unread): caps count only the sync IDs
// kept unread; an ephemeral entry past S's memory cap is refused (12); at the total cap the sync
// ID using most gives way, its oldest entries deleted with no tombstone.
#[test]
fn caps_govern_unread_and_the_largest_gives_way_spec_sync_ids_6() {
    let dev = Dev::new();
    let (s1, s2, r) = (Sid::new(10), Sid::new(40), Sid::new(70));
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s1, Holding::Unread), (&s2, Holding::Unread), (&r, Holding::Read)]));
    for s in [&s1, &s2] {
        st.take_register(&s.id, &s.steps[0].0, None).unwrap();
    }
    st.set_caps(&Caps { policy: BTreeMap::from([("total_bytes".to_string(), 12_000), ("memory_bytes".to_string(), 1500)]), ..Caps::default() });
    let mut first = None;
    for i in 0..4 {
        let (b, x) = blob(2000 + i, Class::Durable, None, &[]);
        assert_eq!(st.take_stamped(&s1.id, &stamped(&s1, b, false), x).unwrap(), Code::OK);
        first.get_or_insert(b);
    }
    let first = first.unwrap();
    let (b, x) = blob(2500, Class::Durable, None, &[]);
    assert_eq!(st.take_stamped(&s2.id, &stamped(&s2, b, false), x).unwrap(), Code::OK);
    assert!(st.entry(&s1.id, &first).unwrap().is_none(), "s1, using most, gave way: its oldest entry");
    assert!(st.tombstone(&s1.id, &first).unwrap().is_none(), "with no tombstone");
    // a read sync ID takes nothing from the room
    let (rb, rx) = blob(9000, Class::Durable, None, &[]);
    let e = Entry { blob: rb, wrap: wrap(1), stamp: None, deposited: false, own: true, role: false, class: Class::Durable, expires: None };
    assert_eq!(st.log(&r.id, e, Some(rx), None).unwrap(), Code::OK);
    assert_eq!(st.entries(&s1.id).unwrap().len(), 3);
    let (eb, ex) = blob(1600, Class::Ephemeral, Some(MAX_DRIFT_MS), &[]);
    assert_eq!(st.take_stamped(&s1.id, &stamped(&s1, eb, false), ex).unwrap(), Code::STORAGE_CAP, "past S's memory cap");
    // r kept unread from now: counted again, it passes the total and, using most, gives way
    st.set_sync_set(&holding(&[(&s1, Holding::Unread), (&s2, Holding::Unread), (&r, Holding::Unread)]));
    assert!(st.settle_at(WallMs(0)).unwrap());
    assert!(st.entry(&r.id, &rb).unwrap().is_none(), "r gave way");
    assert_eq!(st.entries(&s1.id).unwrap().len(), 3, "within the total again: nothing else went");
}

// spec/sync-streams.md §3 (Node log): one log over every sync ID; a read of members skips the
// others; a member ended at `until` is served its events up to it and the later events of
// entries first logged at or below it (spec/sync-streams.md §4); a join reads one sync ID alone.
#[test]
fn log_reads_by_member_and_until_spec_sync_streams_3() {
    let dev = Dev::new();
    let (s1, s2) = (Sid::new(10), Sid::new(40));
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s1, Holding::Unread), (&s2, Holding::Unread)]));
    st.take_register(&s1.id, &s1.steps[0].0, None).unwrap();
    st.take_register(&s2.id, &s2.steps[0].0, None).unwrap();
    let mut bs = Vec::new();
    for i in 0..3 {
        let (b, x) = blob(100 + i, Class::Durable, None, &[]);
        st.take_stamped(&s1.id, &stamped(&s1, b, false), x.clone()).unwrap();
        st.take_stamped(&s2.id, &stamped(&s2, b, false), x).unwrap();
        bs.push(b);
    }
    let only1 = st.read_log(&BTreeMap::from([(s1.id, None)]), None, 100).unwrap();
    assert!(only1.whole && !only1.more);
    assert_eq!(only1.events.len(), 4, "s1's head and three entries");
    assert!(only1.events.iter().all(|e| e.event.sync_id() == s1.id));
    let until = only1.events[2].pos;
    // b0 is first logged before `until`; its delete after is served; b2 (after) is not
    st.take_delete(&s1.id, &[DeleteItem::sign(&s1.delete(), &s1.id, bs[0])], true).unwrap();
    let ended = st.read_log(&BTreeMap::from([(s1.id, Some(until))]), None, 100).unwrap();
    let got: Vec<_> = ended.events.iter().map(|e| e.event).collect();
    assert!(got.contains(&NodeEvent::Deleted { label: s1.id, blob: bs[0], at: 0 }) || got.iter().any(|e| matches!(e, NodeEvent::Deleted { blob, .. } if *blob == bs[0])));
    assert!(!got.contains(&NodeEvent::Added(s1.id, bs[2])));
    let join = st.read_sync(&s2.id, None, None, 100).unwrap();
    assert_eq!(join.events.len(), 4);
    let next = st.read_log(&BTreeMap::from([(s1.id, None), (s2.id, None)]), only1.cursor.as_ref(), 100).unwrap();
    assert!(!next.whole && next.events.len() == 1, "after the cursor: the delete only");
}

// spec/sync-ids.md §5 (Path): each step's claim set is kept until it has been superseded for
// `ROLE_KEEP`; the step stays.
#[test]
fn claim_sets_go_after_role_keep_spec_sync_ids_5() {
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = unread(&dev, &s);
    st.settle_at(WallMs(100)).unwrap();
    let (c1, cs1) = s.rotate(60);
    st.take_register(&s.id, &c1, Some(&cs1)).unwrap();
    st.settle_at(WallMs(100 + ROLE_KEEP_MS - 1)).unwrap();
    assert!(st.path(&s.id).unwrap().unwrap().steps[0].1.is_some());
    st.settle_at(WallMs(100 + ROLE_KEEP_MS)).unwrap();
    let p = st.path(&s.id).unwrap().unwrap();
    assert!(p.steps[0].1.is_none() && p.steps[1].1.is_some(), "the superseded step's set went, the head's stays");
}

// spec/sync-judgement.md §4: the stand of "logged again once" and the deletes seen at a source
// live in its record, durably, until `TOMBSTONE_LIFETIME`; toward a peer with no record they last
// the connection.
#[test]
fn stands_live_in_the_record_spec_sync_judgement_4() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let rec = st.with_tx(|t| t.record_create([1; 32], &[])).unwrap();
    let stand = Stand { at: WallMs(5), logged: BlobId([2; 32]), head: s.head().id(), fall: 3 };
    let (src, conn) = (Source::Record(rec), Source::Conn(ConnId(9)));
    st.set_stand(src, &s.id, b"body", Some(&stand)).unwrap();
    st.set_stand(conn, &s.id, b"body", Some(&stand)).unwrap();
    st.saw_deleted(src, &s.id, &BlobId([3; 32])).unwrap();
    drop(st);
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
    assert_eq!(st.stand(src, &s.id, b"body").unwrap(), Some(stand.clone()), "a restart is no change of ground");
    assert!(st.seen_deleted(src, &s.id, &BlobId([3; 32])).unwrap());
    assert_eq!(st.stand(conn, &s.id, b"body").unwrap(), None, "the connection's went with the start");
    st.set_stand(conn, &s.id, b"body", Some(&stand)).unwrap();
    st.gone(Source::Conn(ConnId(9))).unwrap();
    assert_eq!(st.stand(conn, &s.id, b"body").unwrap(), None, "and with its close");
    st.set_stand(conn, &s.id, b"body", Some(&stand)).unwrap();
    st.settle_at(WallMs(TOMBSTONE_LIFETIME_MS + 5)).unwrap();
    assert_eq!(st.stand(src, &s.id, b"body").unwrap(), None, "aged out");
    assert_eq!(st.stand(conn, &s.id, b"body").unwrap(), None, "a connection's too, however long it lasts");
    assert!(!st.seen_deleted(src, &s.id, &BlobId([3; 32])).unwrap());
}

// spec/sync-set.md §3 (leaving), spec/sync-opens.md §3: shredding S drops every row of it (its
// entries' wraps, tombstones, path, log events) and S from every record, and frees bytes no other
// sync ID names.
#[test]
fn shred_drops_everything_of_s_spec_sync_ids_5() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, x) = blob(100, Class::Durable, None, &[]);
    st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
    let (b2, x2) = blob(101, Class::Durable, None, &[]);
    st.take_stamped(&s.id, &stamped(&s, b2, false), x2).unwrap();
    st.take_delete(&s.id, &[DeleteItem::sign(&s.delete(), &s.id, b2)], true).unwrap();
    let rec = st.with_tx(|t| t.record_create([1; 32], &[])).unwrap();
    st.saw_deleted(Source::Record(rec), &s.id, &b2).unwrap();
    st.shred(&s.id).unwrap();
    assert!(st.entries(&s.id).unwrap().is_empty() && st.path(&s.id).unwrap().is_none());
    assert!(st.tombstone(&s.id, &b2).unwrap().is_none() && st.bytes(&b).unwrap().is_none());
    assert!(events_of(&st, &s.id).is_empty());
    assert_eq!(st.usage(&s.id).unwrap().0, osis_sync::store::Usage::default());
    assert!(!st.seen_deleted(Source::Record(rec), &s.id, &b2).unwrap());
}

/// Every kind of durable store operation, each one transaction: what peers bring (a stamped entry,
/// a deposit charged to a peer's record, a Delete, a Register), the node's own judgement (log,
/// drop, lift, uncharge), the rows `read` keeps in a source's record, the sweeps (the caps giving
/// way, expiry, tombstones and record rows ending) and leaving S. (What a record-less connection
/// brought goes at every start, in the start's one transaction: each reopen below runs it.)
const OPS: usize = 14;

fn ops(st: &mut Store, s: &Sid, rec: RecordId, child: &(Step, ClaimSet), step: usize) {
    let b = |i: usize| blob(100 + i, Class::Durable, Some(5_000), &[]);
    let code = match step {
        0 => st.take_stamped(&s.id, &stamped(s, b(0).0, false), b(0).1).unwrap(),
        1 => st.take_deposit(&deposit(s, &b(1).1, false), Some(Source::Record(rec))).unwrap(),
        2 => st.take_delete(&s.id, &[DeleteItem::sign(&s.delete(), &s.id, b(0).0)], true).unwrap()[0],
        3 => {
            let e = Entry { own: true, expires: Some(WallMs(5_000)), ..stamped(s, b(3).0, false) };
            st.log(&s.id, e, Some(b(3).1), None).unwrap()
        }
        4 => code_of(st.drop_entry(&s.id, &b(3).0, b"note".to_vec()).unwrap()),
        5 => code_of(st.lift_tombstone(&s.id, &b(3).0).unwrap()),
        6 => code_of(st.uncharge(&s.id, &b(1).0).is_ok()),
        7 => code_of(st.set_stand(Source::Record(rec), &s.id, b"body", Some(&Stand { at: WallMs(0), logged: b(7).0, head: s.head().id(), fall: 0 })).is_ok()),
        8 => code_of(st.saw_deleted(Source::Record(rec), &s.id, &b(8).0).is_ok()),
        9 => st.take_stamped(&s.id, &stamped(s, b(9).0, false), b(9).1).unwrap(),
        10 => {
            // the total cap gives way: S's oldest entries go
            st.set_caps(&Caps { policy: BTreeMap::from([("total_bytes".to_string(), 1)]), ..Caps::default() });
            let acted = st.settle_at(WallMs(1_000)).unwrap();
            st.set_caps(&Caps::default());
            code_of(acted)
        }
        11 => st.take_register(&s.id, &child.0, Some(&child.1)).unwrap(),
        12 => code_of(st.settle_at(WallMs(TOMBSTONE_LIFETIME_MS + 2_000)).unwrap()),
        _ => code_of(st.shred(&s.id).is_ok()),
    };
    assert_eq!(code, Code::OK, "op {step}");
}

fn code_of(ok: bool) -> Code {
    if ok { Code::OK } else { Code::REFUSED }
}

/// What the store holds of S that a reader observes: entries, tombstones, events, bytes, path,
/// usage, and the rows `read` keeps of S in `rec`.
fn observe(st: &Store, s: &Sid, rec: RecordId, n: usize) -> String {
    let mut out = format!("{:?}\n{:?}\n{:?}\n", st.entries(&s.id).unwrap(), events_of(st, &s.id), st.path(&s.id).unwrap());
    for i in 0..n {
        let (b, _) = blob(100 + i, Class::Durable, Some(5_000), &[]);
        out += &format!("{:?} {:?}\n", st.tombstone(&s.id, &b).unwrap(), st.bytes(&b).unwrap().map(|v| v.len()));
    }
    out += &format!("{:?}", st.usage(&s.id).unwrap().0);
    let b8 = blob(108, Class::Durable, Some(5_000), &[]).0;
    out += &format!("\n{:?} {:?}", st.stand(Source::Record(rec), &s.id, b"body").unwrap(), st.seen_deleted(Source::Record(rec), &s.id, &b8).unwrap());
    // the record's bytes: its rows, the peer's charge among them
    out += &format!(" {}", st.clone().with_tx(|t| t.records_total()).unwrap());
    out
}

// spec/sync-streams.md §3 (Durability), spec/sync-ids.md §5 (the store is the truth for
// ciphertext): a crash at any durable write of an operation leaves the store as before it or as
// after it, never between (an entry without its event, a removal without its tombstone).
#[test]
fn crash_at_every_write_is_before_or_after_spec_sync_streams_3() {
    let s = Sid::new(10);
    let child = {
        let mut s2 = Sid::new(10);
        s2.rotate(60)
    };
    // a store holding S with a peer's record
    let start = |dev: &Dev| {
        let mut st = unread(dev, &s);
        let rec = st.with_tx(|t| t.record_create([1; 32], &[])).unwrap();
        (st, rec)
    };
    // the store after `ops` 0..n, reopened over its device
    let reopened = |n: usize| {
        let dev = Dev::new();
        let (mut st, rec) = start(&dev);
        for i in 0..n {
            ops(&mut st, &s, rec, &child, i);
        }
        drop(st);
        let mut st = dev.open();
        st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
        observe(&st, &s, rec, OPS)
    };
    for step in 0..OPS {
        let (before, after) = (reopened(step), reopened(step + 1));
        assert_ne!(before, after, "step {step} changes what a reader observes");
        let dev = Dev::new();
        let (mut st, rec) = start(&dev);
        for i in 0..step {
            ops(&mut st, &s, rec, &child, i);
        }
        let w0 = dev.faults.writes();
        ops(&mut st, &s, rec, &child, step);
        let writes = dev.faults.writes() - w0;
        assert!(writes > 0, "step {step} writes durably");
        drop(st);
        for k in 0..writes {
            let dev = Dev::new();
            let (mut st, rec) = start(&dev);
            for i in 0..step {
                ops(&mut st, &s, rec, &child, i);
            }
            dev.faults.at(k, Fault::Crash);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ops(&mut st, &s, rec, &child, step)));
            drop(st);
            dev.faults.revive();
            let mut st = dev.open();
            st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
            let got = observe(&st, &s, rec, OPS);
            assert!(got == before || got == after, "step {step}, crash at write {k} of {writes} (ran: {}):\n{got}\nbefore:\n{before}\nafter:\n{after}", r.is_ok());
        }
    }
}

/// Rows read by `f`, counted (`osis_base::costs`).
fn rows_read(f: impl FnOnce()) -> u64 {
    osis_base::costs::take();
    f();
    osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "store rows read").map(|(.., n)| n).sum()
}

/// A store with `n` entries under each of `others` other sync IDs and `k` under S.
fn filled(n: usize, k: usize) -> (Store, Sid, Option<Vec<u8>>) {
    let dev = Dev::new();
    let s = Sid::new(10);
    let others: Vec<Sid> = (0..2).map(|i| Sid::new(40 + 30 * i)).collect();
    let mut st = dev.open();
    let mut set: Vec<(&Sid, Holding)> = others.iter().map(|o| (o, Holding::Unread)).collect();
    set.push((&s, Holding::Unread));
    st.set_sync_set(&holding(&set));
    for x in others.iter().chain([&s]) {
        st.take_register(&x.id, &x.steps[0].0, None).unwrap();
    }
    for (j, o) in others.iter().enumerate() {
        for i in 0..n {
            let (b, x) = blob(1000 + i + j * 100_000, Class::Durable, None, &[]);
            st.take_stamped(&o.id, &stamped(o, b, false), x).unwrap();
        }
    }
    let cursor = st.read_log(&BTreeMap::from([(s.id, None)]), None, usize::MAX - 1).unwrap().cursor;
    for i in 0..k {
        let (b, x) = blob(500_000 + i, Class::Durable, Some(1_000), &[]);
        st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
    }
    (st, s, cursor)
}

// spec/sync-streams.md §3 (Node log), §4 (Joining): a listing from a cursor costs the events after
// it, and a join from the start costs S's own events: neither grows with what the rest of the
// log holds (counted at n and 10n).
#[test]
fn log_reads_cost_what_they_return_spec_sync_streams_3() {
    let (small, s, c) = filled(20, 5);
    let (large, _, c10) = filled(200, 5);
    let m = BTreeMap::from([(s.id, None)]);
    let a = rows_read(|| assert_eq!(small.read_log(&m, c.as_ref(), 100).unwrap().events.len(), 5));
    let b = rows_read(|| assert_eq!(large.read_log(&m, c10.as_ref(), 100).unwrap().events.len(), 5));
    assert!(a > 0);
    assert_eq!(a, b, "a listing from a cursor: {a} rows at n, {b} at 10n");
    let a = rows_read(|| assert_eq!(small.read_sync(&s.id, None, None, 100).unwrap().events.len(), 6));
    let b = rows_read(|| assert_eq!(large.read_sync(&s.id, None, None, 100).unwrap().events.len(), 6));
    assert_eq!(a, b, "a join from the start: {a} rows at n, {b} at 10n");
}

// spec/sync-ids.md §5 (deleted when no sync ID references them; tombstones), §6 (expiry): removing an entry, and expiring one, costs the same however many
// entries the store holds (counted at n and 10n).
#[test]
fn removal_and_expiry_cost_alike_at_any_size_spec_sync_ids_5() {
    let (mut small, s, _) = filled(20, 3);
    let (mut large, _, _) = filled(200, 3);
    let del = |st: &mut Store| {
        let (b, _) = blob(500_000, Class::Durable, Some(1_000), &[]);
        rows_read(|| assert_eq!(st.take_delete(&s.id, &[DeleteItem::sign(&s.delete(), &s.id, b)], true).unwrap(), [Code::OK]))
    };
    let (a, b) = (del(&mut small), del(&mut large));
    assert_eq!(a, b, "a delete with its blob's reference check: {a} rows at n, {b} at 10n");
    let a = rows_read(|| assert!(small.settle_at(WallMs(1_000)).unwrap()));
    let b = rows_read(|| assert!(large.settle_at(WallMs(1_000)).unwrap()));
    assert_eq!(a, b, "expiring two entries: {a} rows at n, {b} at 10n");
    let a = rows_read(|| assert!(small.settle_at(WallMs(TOMBSTONE_LIFETIME_MS + 1_000)).unwrap()));
    let b = rows_read(|| assert!(large.settle_at(WallMs(TOMBSTONE_LIFETIME_MS + 1_000)).unwrap()));
    assert_eq!(a, b, "ending a tombstone: {a} rows at n, {b} at 10n");
}

// The store's reads are memo-safe (notes/sync-boundary.md, the store's interface): an `Effects`
// value over S's head, or S's entries (durable and ephemeral), is due exactly when a write moves
// what it read, and never for writes elsewhere.
#[test]
fn store_values_are_due_when_their_rows_move() {
    use osis_base::memo::Effects;
    let dev = Dev::new();
    let mut s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let mut heads: Effects<SyncId, Option<Step>> = Effects::new("test heads");
    let mut lists: Effects<SyncId, Vec<Entry>> = Effects::new("test entries");
    heads.want(s.id);
    lists.want(s.id);
    let settle = |heads: &mut Effects<SyncId, Option<Step>>, lists: &mut Effects<SyncId, Vec<Entry>>, st: &Store| {
        for k in heads.due() {
            heads.settle(&k, || st.head(&k).unwrap());
        }
        for k in lists.due() {
            lists.settle(&k, || st.entries(&k).unwrap());
        }
    };
    settle(&mut heads, &mut lists, &st);
    assert!(heads.due().is_empty() && lists.due().is_empty());
    let (b, x) = blob(100, Class::Durable, None, &[]);
    st.take_stamped(&s.id, &stamped(&s, b, false), x).unwrap();
    assert_eq!(lists.due(), [s.id], "an entry added under S");
    assert!(heads.due().is_empty(), "an entry moves no head");
    settle(&mut heads, &mut lists, &st);
    let (e, ex) = blob(101, Class::Ephemeral, Some(10 * MAX_DRIFT_MS), &[]);
    st.take_stamped(&s.id, &stamped(&s, e, false), ex).unwrap();
    assert_eq!(lists.due(), [s.id], "an ephemeral entry added under S");
    settle(&mut heads, &mut lists, &st);
    let other = Sid::new(40);
    st.set_sync_set(&holding(&[(&s, Holding::Unread), (&other, Holding::Unread)]));
    st.take_register(&other.id, &other.steps[0].0, None).unwrap();
    let (o, ox) = blob(102, Class::Durable, None, &[]);
    st.take_stamped(&other.id, &stamped(&other, o, false), ox).unwrap();
    assert!(heads.due().is_empty() && lists.due().is_empty(), "writes under another sync ID");
    let (c1, cs1) = s.rotate(60);
    st.take_register(&s.id, &c1, Some(&cs1)).unwrap();
    assert_eq!(heads.due(), [s.id], "a Register moved the head");
}

// spec: none (internal: notes/sync-boundary.md, store). The deposited index and the entry feed
// follow every entry's flags: a deposit is listed until stamped or removed, durably; the feed
// gives each entry added or changed, once per change.
#[test]
fn deposited_index_and_entry_feed_follow_entries() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s, Holding::Read)]));
    let mut feed = st.entry_feed();
    let (b, bytes) = blob(40, Class::Durable, None, &[]);
    let e = Entry { blob: b, wrap: wrap(3), stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: None };
    assert_eq!(st.log(&s.id, e.clone(), Some(bytes), None).unwrap(), Code::OK);
    assert_eq!(st.deposits(&s.id).unwrap().iter().map(|e| e.blob).collect::<Vec<_>>(), vec![b]);
    assert_eq!(feed.added(), vec![(s.id, b)]);
    assert_eq!(dev.open().all_deposits().unwrap().len(), 1, "durable");
    st.log(&s.id, stamped(&s, b, false), None, None).unwrap();
    assert!(st.deposits(&s.id).unwrap().is_empty() && dev.open().all_deposits().unwrap().is_empty());
    assert_eq!(feed.added(), vec![(s.id, b)], "stamped: changed");
    st.log(&s.id, stamped(&s, b, false), None, None).unwrap();
    assert!(feed.added().is_empty(), "no change, nothing fed");
}

// spec/sync-status.md §2 (a node records each such report): a source's report that an own entry is held elsewhere is
// recorded durably on the entry, kept across a restart and while the entry is, and a relogging
// keeps it; it goes with the entry.
#[test]
fn held_elsewhere_kept_while_the_entry_is() {
    let dev = Dev::new();
    let s = Sid::new(10);
    let mut st = unread(&dev, &s);
    let (b, bytes) = blob(40, Class::Durable, None, &[]);
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b, false), bytes.clone()).unwrap(), Code::OK);
    assert!(!st.elsewhere(&s.id, &b).unwrap());
    assert!(st.first_logged(&s.id, &b).unwrap().is_some());
    st.set_elsewhere(&s.id, &b).unwrap();
    assert!(st.elsewhere(&s.id, &b).unwrap());
    let mut st = dev.open();
    st.set_sync_set(&holding(&[(&s, Holding::Unread)]));
    assert!(st.elsewhere(&s.id, &b).unwrap(), "durable");
    assert_eq!(st.take_stamped(&s.id, &stamped(&s, b, false), bytes).unwrap(), Code::OK);
    assert!(st.elsewhere(&s.id, &b).unwrap(), "taking it again keeps the record");
    assert!(st.drop_entry(&s.id, &b, Vec::new()).unwrap());
    assert!(!st.elsewhere(&s.id, &b).unwrap(), "gone with the entry");
}
