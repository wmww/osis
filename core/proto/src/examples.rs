//! A fixed label (steps, claim set with an entry box, keys) from fixed seeds, and one message of
//! every kind built on it (spec/wire.md §8, §11.2), shared by tests, conformance vectors and fuzz
//! seeds. Fixed inputs only, so construction cannot fail on data.
#![allow(clippy::expect_used)]

use crate::msg::*;
use crate::rbsr::Bound;
use crate::client::Command;
use osis_base::hash::hash;
use osis_base::{BlobId, LabelId, WallMs};
use osis_crypto::{Epoch, LabelRole, SeededRng, Secret32, SigningSecret, X25519Secret, label_role_key};
use osis_label::{Parent, Prefix, Reader, StepKeys, genesis_label, register, sign_deposit, sign_stamp};
use osis_label::step::EntryTo;

/// The server's static key and Hello challenge the examples sign opens for.
pub const STATIC_KEY: [u8; 32] = [0x5e; 32];
pub const CHALLENGE: [u8; 32] = [0x40; 32];

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One group's label at index 0: a genesis step and a child without rotation, each with a claim
/// set listing one DH reader and one key actor (symmetric entry box).
pub struct Fixture {
    pub label: LabelId,
    pub genesis: Step,
    pub genesis_claims: ClaimSet,
    pub child: Step,
    pub child_claims: ClaimSet,
    pub sync: SigningSecret,
    pub write: SigningSecret,
    pub delete: SigningSecret,
    pub deposit: SigningSecret,
    /// The DH reader's X25519 key (its claim key: `step.claim_key(&reader)`).
    pub reader: X25519Secret,
    /// The key actor listed by static entry.
    pub key_actor: SigningSecret,
}

impl Fixture {
    /// Group secrets from bytes `b..b+3`, deposit seed `b+3`; reader `b+4`; key actor `b+5`.
    pub fn new(b: u8) -> Fixture {
        let (read, write, admin, dseed) = (s32(b), s32(b + 1), s32(b + 2), s32(b + 3));
        let label = genesis_label(&admin, 0);
        let keys = StepKeys::derive(&read, &write, &admin, 0, &dseed, &label);
        let delete = label_role_key(LabelRole::Delete, &admin, 0);
        let reader = X25519Secret::from_secret(&s32(b + 4));
        let key_actor = SigningSecret::from_seed(&s32(b + 5));
        let s = s32(b + 6);
        let epoch_s = Epoch::new(0, [b; 16]).expect("small epoch");
        let read_epoch = Epoch::new(1, [b + 1; 16]).expect("small epoch");
        let readers = [Reader::Dh(reader.public()), Reader::Static { signing: key_actor.verifying_key(), entry: EntryTo::Symmetric { s: &s, epoch_s } }];
        let mut rng = SeededRng::from_seed([b + 7; 32]);
        let (genesis, genesis_claims) = register(Parent::Genesis(&delete), keys, &readers, (read_epoch, &read), &mut rng).expect("fixed genesis");
        let (child, child_claims) = register(Parent::Child { step: &genesis, delete: &delete }, keys, &readers, (read_epoch, &read), &mut rng).expect("fixed child");
        Fixture {
            label,
            genesis,
            genesis_claims,
            child,
            child_claims,
            sync: label_role_key(LabelRole::Sync, &read, 0),
            write: label_role_key(LabelRole::Write, &write, 0),
            delete,
            deposit: osis_crypto::deposit_key(&dseed, &label),
            reader,
            key_actor,
        }
    }

    /// A framed blob of `n`-derived plaintext under a prefix with salt `n` and no expiry.
    pub fn blob(n: u8) -> Vec<u8> {
        Fixture::blob_with(n, None, vec![])
    }

    pub fn blob_with(n: u8, expiry: Option<u64>, commitments: Vec<[u8; 33]>) -> Vec<u8> {
        let p = Prefix::new([n; 16], expiry.map(WallMs), commitments).expect("fixed prefix");
        osis_label::frame(&p, &[n; 20], &mut SeededRng::from_seed([n; 32])).expect("small blob").1
    }

    /// A stamped entry of `blob` under the head's write key (wrap: 49 repeated bytes).
    pub fn entry(&self, blob: Vec<u8>) -> Entry {
        let wrap = [blob.len() as u8; WRAP_LEN];
        let stamp = sign_stamp(&self.write, &self.label, &osis_label::blob_id(&blob), &wrap);
        Entry { blob, wrap, stamp, replaces: Vec::new() }
    }
}

/// One label's signing keys at one step.
#[derive(Clone)]
pub struct Keys {
    pub sync: SigningSecret,
    pub write: SigningSecret,
    pub delete: SigningSecret,
    pub deposit: SigningSecret,
}

/// A label that rotates (engine and server tests): its path, claim sets and keys; group secrets
/// from a byte each, the admin secret from `admin`.
pub struct Label {
    pub id: LabelId,
    pub keys: Vec<Keys>,
    pub steps: Vec<Step>,
    pub sets: Vec<ClaimSet>,
    pub reader: X25519Secret,
    /// The key actor every claim set lists by static entry.
    pub key_actor: SigningSecret,
    pub admin: u8,
}

const DEPOSIT_SEED: u8 = 0x30;

impl Label {
    pub fn new(admin: u8) -> Label {
        let id = genesis_label(&s32(admin), 0);
        let mut l = Label { id, keys: vec![], steps: vec![], sets: vec![], reader: X25519Secret::from_secret(&s32(0x31)), key_actor: SigningSecret::from_seed(&s32(0x32)), admin };
        l.step_with(1, None);
        l
    }

    /// A step with read secret `b`, write `b + 1`, the admin secret (a child of the head signed
    /// by `parent`, else the genesis step).
    fn step_with(&mut self, b: u8, parent: Option<SigningSecret>) -> (Step, ClaimSet) {
        let (read, write, adm) = (s32(b), s32(b + 1), s32(self.admin));
        let pk = StepKeys::derive(&read, &write, &adm, 0, &s32(DEPOSIT_SEED), &self.id);
        let keys = Keys {
            sync: label_role_key(LabelRole::Sync, &read, 0),
            write: label_role_key(LabelRole::Write, &write, 0),
            delete: label_role_key(LabelRole::Delete, &adm, 0),
            deposit: osis_crypto::deposit_key(&s32(DEPOSIT_SEED), &self.id),
        };
        let s = s32(0x33);
        let readers = [Reader::Dh(self.reader.public()), Reader::Static { signing: self.key_actor.verifying_key(), entry: EntryTo::Symmetric { s: &s, epoch_s: Epoch::new(0, [0; 16]).expect("small epoch") } }];
        let mut rng = SeededRng::from_seed([b; 32]);
        let read_epoch = (Epoch::new(1, [b; 16]).expect("small epoch"), &read);
        let (step, set) = match (&parent, self.steps.last()) {
            (Some(d), Some(prev)) => register(Parent::Child { step: prev, delete: d }, pk, &readers, read_epoch, &mut rng).expect("child step"),
            _ => register(Parent::Genesis(&keys.delete), pk, &readers, read_epoch, &mut rng).expect("genesis step"),
        };
        self.steps.push(step.clone());
        self.sets.push(set.clone());
        self.keys.push(keys);
        (step, set)
    }

    /// A child step under new read and write secrets (`b`, `b + 1`).
    pub fn rotate(&mut self, b: u8) -> (Step, ClaimSet) {
        let parent = self.head_keys().delete.clone();
        self.step_with(b, Some(parent))
    }

    pub fn head_keys(&self) -> &Keys {
        self.keys.last().expect("a label has a step")
    }

    /// A stamped entry of `blob` under the head's write key.
    pub fn entry(&self, blob: Vec<u8>) -> Entry {
        self.entry_by(blob, &self.head_keys().write.clone())
    }

    pub fn entry_by(&self, blob: Vec<u8>, write: &SigningSecret) -> Entry {
        let wrap: Wrap = [(blob.len() % 251) as u8; WRAP_LEN];
        let stamp = sign_stamp(write, &self.id, &osis_label::blob_id(&blob), &wrap);
        Entry { blob, wrap, stamp, replaces: Vec::new() }
    }

    pub fn deposit(&self, blob: Vec<u8>, key: &SigningSecret) -> Command {
        let wrap: Wrap = [7; WRAP_LEN];
        let sig = sign_deposit(key, &self.id, &osis_label::blob_id(&blob), &wrap);
        Command::Deposit { label: self.id, blob, wrap, sig }
    }

    /// Registers step `i` with its claim set.
    pub fn register_cmd(&self, i: usize) -> Command {
        Command::Register { label: self.id, step: self.steps.get(i).expect("step").clone(), claim_set: self.sets.get(i).cloned() }
    }
}

/// A prefix salt from `n`.
pub fn salt(n: u64) -> [u8; 16] {
    hash(&n.to_be_bytes()).first_chunk::<16>().copied().unwrap_or_default()
}

/// A blob with a version 1 prefix (salt from `n`, expiry unless 0, commitments), then `size`
/// body bytes.
pub fn blob_sized(n: u64, expiry: u64, commitments: Vec<[u8; 33]>, size: usize) -> Vec<u8> {
    let mut b = Prefix::new(salt(n), (expiry != 0).then_some(WallMs(expiry)), commitments).expect("small prefix").to_bytes();
    let h = hash(&n.to_le_bytes());
    b.extend(h.iter().cycle().take(size));
    b
}

pub fn blob_with(n: u64, expiry: u64, commitments: Vec<[u8; 33]>) -> Vec<u8> {
    blob_sized(n, expiry, commitments, 20 + (n % 32) as usize)
}

pub fn blob(n: u64) -> Vec<u8> {
    blob_with(n, 0, vec![])
}

pub fn bid(n: u64) -> BlobId {
    osis_label::blob_id(&blob(n))
}

/// `(name, message)` for every kind, in kind order, plus variants of the sum types.
pub fn messages() -> Vec<(&'static str, Message)> {
    let f = Fixture::new(0x10);
    let l = f.label;
    let id = |b: u8| BlobId([b; 32]);
    let cursor = Cursor { log_id: [0x1c; 16], seq: 42 };
    let entry = f.entry(Fixture::blob(1));
    let added = Event::Added { blob_id: osis_label::blob_id(&entry.blob), blob: Some(entry.blob.clone()), wrap: entry.wrap, stamp: Some(entry.stamp) };
    let entry_box = f.genesis_claims.entry_box(&l, &f.key_actor.verifying_key()).cloned();
    let claim = f.genesis.claim_key(&f.reader).expect("claim key");
    let deposited = Fixture::blob(2);
    let dep_wrap = [0x78; WRAP_LEN];
    let dep_sig = osis_label::sign_deposit(&f.deposit, &l, &osis_label::blob_id(&deposited), &dep_wrap);
    let dk = osis_crypto::DeleteSecret::derive(&s32(0x7a));
    vec![
        ("error", Message::Error { id: 1, code: Code::NOT_OPENED }),
        ("ok", Message::Ok { id: 2 }),
        ("ping", Message::Ping { id: 3, wall_ms: 1_700_000_000_000 }),
        ("pong", Message::Pong { id: 3, wall_ms: 1_700_000_000_123 }),
        ("open sync key", Message::Open { id: 4, label: l, proof: Proof::sync(&f.sync, &l, &CHALLENGE, &STATIC_KEY) }),
        ("open claim key", Message::Open { id: 5, label: l, proof: Proof::claim(f.genesis.id(), &claim, &l, &CHALLENGE, &STATIC_KEY) }),
        ("open static entry", Message::Open { id: 6, label: l, proof: Proof::static_entry(&f.key_actor, &l, &CHALLENGE, &STATIC_KEY) }),
        ("open member proof", Message::Open { id: 9, label: l, proof: Proof::member(&SigningSecret::from_seed(&s32(0x7c)), &l, &CHALLENGE, &STATIC_KEY) }),
        ("opened", Message::Opened { id: 4, head: f.child.clone(), entry_box: None }),
        ("opened with entry box", Message::Opened { id: 6, head: f.genesis.clone(), entry_box }),
        ("step", Message::Step { id: 4, step: f.child.clone() }),
        ("register", Message::Register { id: 7, label: l, step: f.genesis.clone(), claim_set: Some(f.genesis_claims.clone()) }),
        ("path", Message::Path { id: 8, label: l, after: Some(f.genesis.id()) }),
        ("path reply", Message::PathReply { id: 8, steps: vec![f.genesis.clone(), f.child.clone()], more: false }),
        ("upload", Message::Upload { id: 10, label: l, entries: vec![entry.clone()] }),
        (
            "upload with replaces",
            Message::Upload {
                id: 11,
                label: l,
                entries: vec![Entry {
                    replaces: vec![
                        Replace::Untie(id(0xe1)),
                        Replace::Delete(DeleteItem::sign(&f.delete, &l, id(0xe2), None).expect("fixed delete")),
                        Replace::Delete(DeleteItem::sign_by(&f.write, &dk, 3, &[0x7d; 16], &[0x7e; 16], &l, id(0xe3), None).expect("fixed delete")),
                    ],
                    ..f.entry(Fixture::blob(4))
                }],
            },
        ),
        ("status", Message::Status { id: 10, codes: vec![Code::OK, Code::NOT_HEAD], head: Some(f.child.clone()) }),
        ("deposit", Message::Deposit { id: 12, label: l, blob: deposited, wrap: dep_wrap, sig: dep_sig }),
        ("budget", Message::Budget { id: 12, code: Code::OK, entries_left: 63, bytes_left: 2_064_384, head: None }),
        ("delete", Message::Delete { id: 14, label: l, items: vec![DeleteItem::sign(&f.delete, &l, id(0xd1), None).expect("fixed delete"), DeleteItem::sign_by(&f.sync, &dk, 2, &[0x7d; 16], &[0x7e; 16], &l, id(0xd2), Some(WallMs(1_700_000_100_000))).expect("fixed delete")] }),
        ("cursor sync", Message::Sync { id: 15, label: l, cursor: Some(cursor), inline_limit: 65_536, entries: vec![entry], gained: vec![id(0xa1), id(0xa2)] }),
        ("sync without cursor", Message::Sync { id: 16, label: l, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] }),
        (
            "sync reply",
            Message::SyncReply {
                id: 15,
                events: vec![
                    added.clone(),
                    Event::Added { blob_id: id(0xb2), blob: None, wrap: [0x79; WRAP_LEN], stamp: None },
                    Event::Deleted(id(0xb3)),
                    Event::Pending { blob_id: id(0xb4), at: 1_700_000_200_000 },
                    Event::Head(f.child.clone()),
                ],
                want: vec![id(0xa2)],
                codes: vec![Code::OK],
                cursor: Cursor { log_id: [0x1c; 16], seq: 47 },
                more: false,
            },
        ),
        (
            "reconcile",
            Message::Reconcile {
                id: 17,
                label: l,
                ranges: vec![
                    Range { lower: Bound::empty(), upper: Bound::of(&id(0x40)), mode: Mode::Fingerprint([0xf1; 16]) },
                    Range { lower: Bound::of(&id(0x40)), upper: Bound::new(vec![0x80]).unwrap_or_default(), mode: Mode::Ids(vec![id(0x41), id(0x42)]) },
                ],
            },
        ),
        (
            "reconcile reply",
            Message::ReconcileReply {
                id: 17,
                ranges: vec![Range { lower: Bound::of(&id(0x40)), upper: Bound::new(vec![0x80]).unwrap_or_default(), mode: Mode::Diff { theirs: vec![id(0x43)], lacking: vec![id(0x42)] } }],
            },
        ),
        ("fetch", Message::Fetch { id: 19, label: l, ids: vec![id(0xb2), id(0xb5)] }),
        (
            "fetch reply",
            Message::FetchReply { id: 19, items: vec![Fetched { blob_id: id(0xb2), entry: Some((Fixture::blob(3), [0x79; WRAP_LEN], None)) }, Fetched { blob_id: id(0xb5), entry: None }] },
        ),
        ("subscribe", Message::Subscribe { id: 21, labels: vec![l, LabelId([0x0b; 16])] }),
        ("unsubscribe", Message::Unsubscribe { id: 22, labels: vec![l] }),
        ("push", Message::Push { label: l, events: vec![added], cursor: Cursor { log_id: [0x1c; 16], seq: 48 } }),
    ]
}
