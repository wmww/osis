//! A fixed label (steps, claim set with an entry box, keys) from fixed seeds, and one message of
//! every kind built on it (spec/wire.md §8, §11.2), shared by tests, conformance vectors and fuzz
//! seeds. Fixed inputs only, so construction cannot fail on data.
#![allow(clippy::expect_used)]

use crate::msg::*;
use osis_base::hash::hash;
use osis_base::{BlobId, LabelId, WallMs};
use osis_crypto::{Epoch, KemSecret, LabelRole, SeededRng, Secret32, SigningSecret, X25519Secret, label_role_key};
use osis_label::{Parent, Prefix, Reader, StepKeys, genesis_label, register, sign_deposit, sign_stamp};

/// The host's static key and Hello challenge the examples sign opens for.
pub const STATIC_KEY: [u8; 32] = [0x5e; 32];
pub const CHALLENGE: [u8; 32] = [0x40; 32];

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One group's label: a genesis step and a child without rotation, each with a claim
/// set listing one DH reader and one key actor (entry box sealed to a KEM key from `b+6`).
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
    /// Group secrets from bytes `b..b+3`, deposit seed `b+3`; reader `b+4`; key actor `b+5`;
    /// sync secret `b+8`.
    pub fn new(b: u8) -> Fixture {
        let (read, write, admin, dseed, sync) = (s32(b), s32(b + 1), s32(b + 2), s32(b + 3), s32(b + 8));
        let label = genesis_label(&admin);
        let keys = StepKeys::derive(&sync, &write, &admin, &dseed, &label);
        let delete = label_role_key(LabelRole::Delete, &admin);
        let reader = X25519Secret::from_secret(&s32(b + 4));
        let key_actor = SigningSecret::from_seed(&s32(b + 5));
        let kem = KemSecret::derive(&s32(b + 6));
        let group = osis_base::Tid::from_bytes([b; 15]);
        let read_epoch = Epoch::derive(&group, osis_base::Role::Read, 1, &read).expect("small epoch");
        let sync_epoch = Epoch::derive(&group, osis_base::Role::Sync, 1, &sync).expect("small epoch");
        let readers = [Reader::Dh(reader.public()), Reader::Static { signing: key_actor.verifying_key(), kem: kem.public() }];
        let mut rng = SeededRng::from_seed([b + 7; 32]);
        let (genesis, genesis_claims) = register(Parent::Genesis(&delete), keys, &readers, (&group, read_epoch, &read), (sync_epoch, &sync), &mut rng).expect("fixed genesis");
        let (child, child_claims) = register(Parent::Child { step: &genesis, delete: &delete }, keys, &readers, (&group, read_epoch, &read), (sync_epoch, &sync), &mut rng).expect("fixed child");
        Fixture {
            label,
            genesis,
            genesis_claims,
            child,
            child_claims,
            sync: label_role_key(LabelRole::Sync, &sync),
            write: label_role_key(LabelRole::Write, &write),
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
        let p = Prefix::new([n; 16], expiry.map(WallMs), if commitments.is_empty() { vec![] } else { vec![commitments] }).expect("fixed prefix");
        osis_label::frame(&p, &[n; 20], &mut SeededRng::from_seed([n; 32])).expect("small blob").1
    }

    /// A stamped entry of `blob` under the head's write key (wrap: one byte repeated).
    pub fn entry(&self, blob: Vec<u8>) -> Stamped {
        let wrap = [blob.len() as u8; WRAP_LEN];
        let stamp = sign_stamp(&self.write, &self.label, &osis_label::blob_id(&blob), &wrap, false);
        Stamped { blob, wrap, stamp }
    }
}

/// A blob with its wrap and its stamp under a write key.
#[derive(Clone, Debug)]
pub struct Stamped {
    pub blob: Vec<u8>,
    pub wrap: Wrap,
    pub stamp: Signature,
}

/// One label's signing keys at one step.
#[derive(Clone)]
pub struct Keys {
    pub sync: SigningSecret,
    pub write: SigningSecret,
    pub delete: SigningSecret,
    pub deposit: SigningSecret,
}

/// A label that rotates (engine and host tests): its path, claim sets and keys; group secrets
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
    /// Each step's sync secret byte.
    syncs: Vec<u8>,
}

const DEPOSIT_SEED: u8 = 0x30;

impl Label {
    pub fn new(admin: u8) -> Label {
        let id = genesis_label(&s32(admin));
        let mut l = Label { id, keys: vec![], steps: vec![], sets: vec![], reader: X25519Secret::from_secret(&s32(0x31)), key_actor: SigningSecret::from_seed(&s32(0x32)), admin, syncs: vec![] };
        l.step_with(1, 1, None);
        l
    }

    /// A step with read secret `b`, write `b + 1`, sync `sync ^ 0x80`, the admin secret (a child
    /// of the head signed by `parent`, else the genesis step).
    fn step_with(&mut self, b: u8, sync: u8, parent: Option<SigningSecret>) -> (Step, ClaimSet) {
        self.syncs.push(sync);
        let (read, write, adm, sync) = (s32(b), s32(b + 1), s32(self.admin), s32(sync ^ 0x80));
        let pk = StepKeys::derive(&sync, &write, &adm, &s32(DEPOSIT_SEED), &self.id);
        let keys = Keys {
            sync: label_role_key(LabelRole::Sync, &sync),
            write: label_role_key(LabelRole::Write, &write),
            delete: label_role_key(LabelRole::Delete, &adm),
            deposit: osis_crypto::deposit_key(&s32(DEPOSIT_SEED), &self.id),
        };
        let kem = KemSecret::derive(&s32(0x33));
        let readers = [Reader::Dh(self.reader.public()), Reader::Static { signing: self.key_actor.verifying_key(), kem: kem.public() }];
        let mut rng = SeededRng::from_seed([b; 32]);
        let group = osis_base::Tid::from_bytes([b; 15]);
        let read_epoch = (&group, Epoch::derive(&group, osis_base::Role::Read, 1, &read).expect("small epoch"), &read);
        let sync_epoch = (Epoch::derive(&group, osis_base::Role::Sync, 1, &sync).expect("small epoch"), &sync);
        let (step, set) = match (&parent, self.steps.last()) {
            (Some(d), Some(prev)) => register(Parent::Child { step: prev, delete: d }, pk, &readers, read_epoch, sync_epoch, &mut rng).expect("child step"),
            _ => register(Parent::Genesis(&keys.delete), pk, &readers, read_epoch, sync_epoch, &mut rng).expect("genesis step"),
        };
        self.steps.push(step.clone());
        self.sets.push(set.clone());
        self.keys.push(keys);
        (step, set)
    }

    /// A child step under new read and write secrets (`b`, `b + 1`).
    pub fn rotate(&mut self, b: u8) -> (Step, ClaimSet) {
        let parent = self.head_keys().delete.clone();
        self.step_with(b, b, Some(parent))
    }

    /// A child step under new read and write secrets (`b`, `b + 1`) and the head's sync secret.
    pub fn rotate_keeping_sync(&mut self, b: u8) -> (Step, ClaimSet) {
        let parent = self.head_keys().delete.clone();
        let sync = self.syncs.last().copied().unwrap_or(1);
        self.step_with(b, sync, Some(parent))
    }

    pub fn head_keys(&self) -> &Keys {
        self.keys.last().expect("a label has a step")
    }

    /// A stamped entry of `blob` under the head's write key.
    pub fn entry(&self, blob: Vec<u8>) -> Stamped {
        self.entry_by(blob, &self.head_keys().write.clone())
    }

    pub fn entry_by(&self, blob: Vec<u8>, write: &SigningSecret) -> Stamped {
        let wrap: Wrap = [(blob.len() % 251) as u8; WRAP_LEN];
        let stamp = sign_stamp(write, &self.id, &osis_label::blob_id(&blob), &wrap, false);
        Stamped { blob, wrap, stamp }
    }

    /// A Deposit item of `blob` signed by `key`.
    pub fn deposit(&self, blob: Vec<u8>, key: &SigningSecret) -> crate::msg::OfferItem {
        let wrap: Wrap = [7; WRAP_LEN];
        let sig = sign_deposit(key, &self.id, &osis_label::blob_id(&blob), &wrap, false);
        crate::msg::OfferItem::Deposit { label: self.id, blob, wrap, sig }
    }

    /// A Register of step `i` with its claim set, as request `id`.
    pub fn register(&self, id: crate::msg::Id, i: usize) -> crate::msg::Message {
        crate::msg::Message::Register { id, label: self.id, step: self.steps.get(i).expect("step").clone(), claim_set: self.sets.get(i).cloned() }
    }
}

/// A prefix salt from `n`.
pub fn salt(n: u64) -> [u8; 16] {
    hash(&n.to_be_bytes()).first_chunk::<16>().copied().unwrap_or_default()
}

/// A blob with a version 1 prefix (salt from `n`, expiry unless 0, commitments), then `size`
/// body bytes.
pub fn blob_sized(n: u64, expiry: u64, commitments: Vec<[u8; 33]>, size: usize) -> Vec<u8> {
    let mut b = Prefix::new(salt(n), (expiry != 0).then_some(WallMs(expiry)), if commitments.is_empty() { vec![] } else { vec![commitments] }).expect("small prefix").to_bytes();
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
    let entry = f.entry(Fixture::blob(1));
    let added = Event::Added { blob_id: osis_label::blob_id(&entry.blob), blob: Some(entry.blob.clone()), wrap: entry.wrap, stamp: Some(entry.stamp) };
    let entry_box = f.genesis_claims.entry_box(&l, &f.key_actor.verifying_key()).cloned();
    let deposited = Fixture::blob(2);
    let dep_wrap = [0x78; WRAP_LEN];
    let dep_sig = osis_label::sign_deposit(&f.deposit, &l, &osis_label::blob_id(&deposited), &dep_wrap, false);
    let dk = osis_crypto::DeleteSecret::derive(&s32(0x7a));
    vec![
        ("error", Message::Error { id: 1, code: Code::NOT_OPENED }),
        ("ok", Message::Ok { id: 2 }),
        ("ping", Message::Ping { id: 3, wall_ms: 1_700_000_000_000 }),
        ("pong", Message::Pong { id: 3, wall_ms: 1_700_000_000_123 }),
        ("register", Message::Register { id: 7, label: l, step: f.genesis.clone(), claim_set: Some(f.genesis_claims.clone()) }),
        ("status", Message::Status { id: 10, codes: vec![Code::OK, Code::NOT_HEAD] }),
        ("delete", Message::Delete { id: 14, label: l, items: vec![DeleteItem::sign(&f.delete, &l, id(0xd1)).expect("fixed delete"), DeleteItem::sign_by(&f.sync, &[(2, &dk)], &[0x7d; 16], &[0x7e; 16], &l, id(0xd2)).expect("fixed delete")] }),
        ("fetch", Message::Fetch { id: crate::msg::NODE_IDS | 19, label: l, max_reply: 32_768, ids: vec![id(0xb2), id(0xb5)] }),
        (
            "fetch reply",
            Message::FetchReply { id: crate::msg::NODE_IDS | 19, items: vec![Fetched { blob_id: id(0xb2), entry: Some((Fixture::blob(3), [0x79; WRAP_LEN], None)) }, Fetched { blob_id: id(0xb5), entry: None }] },
        ),
        (
            "stranded",
            Message::Stranded {
                id: 35,
                label: l,
                holder: osis_base::Tid::from_bytes([0x0d; 15]),
                keys: osis_label::HolderKeys { commits: vec![osis_base::Value::List(vec![osis_base::Value::List(vec![]), osis_base::Value::Int(1), osis_base::Value::List(vec![])])], records: vec![osis_base::CreationRecord::Thing { admin: osis_base::Tid::from_bytes([0x0e; 15]), nonce: [0x0f; 32], link: None }] },
            },
        ),
        ("suspect", Message::Suspect { id: 36, label: l, entries: vec![crate::msg::SuspectEntry { thing: osis_base::Tid::from_bytes([0x0c; 15]), ak: osis_base::Ak::new("t:reg.0").expect("an AK"), digest: [0x0d; 16] }] }),
        ("beacons", Message::Beacons { id: 30, generation: 1, base: None, f: 9, lo: 0, hi: 512, gcs: vec![0, 1, 2], more: false }),
        ("offer", Message::Offer { id: 31, items: vec![crate::msg::OfferItem::Hit([9; 32], None), crate::msg::OfferItem::Hit([10; 32], Some(osis_crypto::Signature([11; 64]))), crate::msg::OfferItem::ByRole(l, vec![[8; 32]])] }),
        ("offer with a deposit", Message::Offer { id: 34, items: vec![crate::msg::OfferItem::Deposit { label: l, blob: deposited, wrap: dep_wrap, sig: dep_sig }] }),
        ("offer static", Message::Offer { id: 36, items: vec![crate::msg::OfferItem::Static { hit: [12; 32], key: f.key_actor.verifying_key().to_bytes(), sig: osis_crypto::sign_open(&f.key_actor, &l, &CHALLENGE, &STATIC_KEY) }] }),
        ("offer behind", Message::Offer { id: 35, items: vec![crate::msg::OfferItem::Behind { label: l, step: Some(f.genesis.id()), key: f.sync.verifying_key().to_bytes(), sig: osis_crypto::sign_open(&f.sync, &l, &CHALLENGE, &STATIC_KEY) }, crate::msg::OfferItem::Behind { label: l, step: None, key: f.sync.verifying_key().to_bytes(), sig: osis_crypto::sign_open(&f.sync, &l, &CHALLENGE, &STATIC_KEY) }] }),
        ("lost", Message::Lost { id: 32, items: vec![(l, None)] }),
        ("shared", Message::Shared { id: 31, codes: vec![(Code::OK, Some([7; 32]), None), (Code::NOT_ADMITTED, None, None)] }),
        ("shared with an entry grant", Message::Shared { id: 32, codes: vec![(Code::OK, Some([7; 32]), Some(Box::new(crate::msg::Grant { entry_box: Some(entry_box.expect("the key actor is listed")), steps: vec![f.genesis.clone(), f.child.clone()] })))] }),
        ("shared with a child step", Message::Shared { id: 35, codes: vec![(Code::OK, None, Some(Box::new(crate::msg::Grant { entry_box: None, steps: vec![f.child.clone()] })))] }),
        ("no record", Message::NoRecord { id: 33 }),
        (
            "pull",
            Message::Pull(Box::new(crate::msg::Pull { id: 34, cursor: Some(vec![0x2c; 72]), joins: vec![(l, None), (LabelId([0x0b; 16]), Some(vec![0x2d; 72]))], inline_limit: 0, max_reply: 65_536, follow: true, ephemeral: true })),
        ),
        (
            "pull reply",
            Message::PullReply(Box::new(crate::msg::PullReply { id: 34, events: vec![(l, added.clone()), (l, Event::Deleted(id(0xb7)))], cursor: Some(vec![0x2e; 72]), whole: false, trimmed: false, more: true, report: false, joins: vec![(LabelId([0x0b; 16]), Some(vec![0x2f; 72]))] })),
        ),
        ("stream", Message::Stream(Box::new(crate::msg::Stream { events: vec![(l, added.clone())], cursor: Some(vec![0x30; 72]), report: true }))),
        ("applied", Message::Applied { cursor: vec![0x30; 72] }),
        ("digest", Message::Digest { digest: [0x31; 32] }),
        ("members", Message::Members { labels: vec![l, LabelId([0x0b; 16])], more: false }),
    ]
}

/// Tests only: a hand-driven dialer, a dialer `Session` over an empty store that picks its
/// requests' ids (below `NODE_IDS`, as a node does for its own) and keeps what the session hands
/// up. Its requests and answers go through the session as any upper layer's do.
pub struct Dialer {
    pub session: crate::Session,
    store: crate::MemoryLabelStore,
    next: Id,
}

impl Dialer {
    /// A dialer of the listener of static key `listener_key`, its Hello challenge `challenge`.
    pub fn new(listener_key: [u8; 32], challenge: [u8; 32]) -> Dialer {
        let cfg = crate::SessionConfig { listener_key, challenge, dialed: true };
        Dialer { session: crate::Session::new(cfg), store: crate::MemoryLabelStore::new(), next: 0 }
    }

    pub fn handle(&mut self, now: u64, input: crate::SessionInput) -> Vec<crate::SessionOutput> {
        self.session.handle(now, &mut self.store, input)
    }

    /// The connection is up: its Hello.
    pub fn start(&mut self, now: u64) -> Vec<crate::SessionOutput> {
        self.handle(now, crate::SessionInput::Start)
    }

    /// Bytes from the listener.
    pub fn bytes(&mut self, now: u64, b: Vec<u8>) -> Vec<crate::SessionOutput> {
        self.handle(now, crate::SessionInput::Bytes(b))
    }

    /// The next id below `NODE_IDS`.
    pub fn next_id(&mut self) -> Id {
        self.next = (self.next.wrapping_add(1) & !NODE_IDS).max(1);
        self.next
    }

    /// Request `m` under the next id: the id, and what the session put out.
    pub fn request(&mut self, now: u64, m: impl FnOnce(Id) -> Message) -> (Id, Vec<crate::SessionOutput>) {
        let id = self.next_id();
        (id, self.send(now, m(id)))
    }

    /// Sends `m` as is (an answer, a push, or a request under an id of the caller's).
    pub fn send(&mut self, now: u64, m: Message) -> Vec<crate::SessionOutput> {
        self.handle(now, crate::SessionInput::Peer(Box::new(m)))
    }

    /// This dialer's Prove of `provers`, signed over the binding (none before the Hellos).
    pub fn prove(&mut self, now: u64, provers: &[crate::Prover]) -> Option<(Id, Vec<crate::SessionOutput>)> {
        let (_, listener, key) = self.session.binding()?;
        let proofs = provers.iter().map(|p| p.sign(false, &listener, &key)).collect();
        Some(self.request(now, |id| Message::Prove { id, proofs }))
    }

    /// The listener's proofs in `proved` that verify over this connection (`prove::verified`).
    pub fn verified(&self, proved: Vec<crate::ActorProof>) -> Vec<crate::ActorProof> {
        let Some((dialer, _, key)) = self.session.binding() else { return Vec::new() };
        crate::prove::verified(proved, true, &dialer, &key)
    }
}

/// The frames in `out`.
pub fn frames(out: &[crate::SessionOutput]) -> Vec<Vec<u8>> {
    out.iter().filter_map(|o| if let crate::SessionOutput::Send(f) = o { Some(f.clone()) } else { None }).collect()
}

/// The messages `out` hands up (`SessionOutput::Peer`).
pub fn up(out: &[crate::SessionOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let crate::SessionOutput::Peer(m) = o { Some((**m).clone()) } else { None }).collect()
}
