//! A fixed sync ID (steps, claim set with an entry box, keys) from fixed seeds, one message of
//! every kind built on it and one rejection per kind (spec/wire.md §8, §11.2), shared by tests,
//! conformance vectors and fuzz seeds. Fixed inputs only, so construction cannot fail on data.
#![allow(clippy::expect_used)]

use crate::api::{Outcome, Payload};
use crate::msg::*;
use crate::{ActorProof, Prover, SyncId};
use osis_base::{BlobId, CreationRecord, Tid, Value, WallMs, cbor};
use osis_crypto::{Epoch, KemSecret, LabelRole, SeededRng, Secret32, SigningSecret, X25519Secret, label_role_key};
use osis_label::{Parent, Prefix, Reader, StepKeys, genesis_label, register, sign_stamp};

/// The listener's static key and the Hello challenge the examples sign opens and proofs for.
pub const STATIC_KEY: [u8; 32] = [0x5e; 32];
pub const CHALLENGE: [u8; 32] = [0x40; 32];

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One group's sync ID: a genesis step and a child without rotation, each with a claim
/// set listing one DH reader and one key actor (entry box sealed to a KEM key from `b+6`).
pub struct Fixture {
    pub sync_id: SyncId,
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
        let sync_id = genesis_label(&admin);
        let keys = StepKeys::derive(&sync, &write, &admin, &dseed, &sync_id);
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
            sync_id,
            genesis,
            genesis_claims,
            child,
            child_claims,
            sync: label_role_key(LabelRole::Sync, &sync),
            write: label_role_key(LabelRole::Write, &write),
            delete,
            deposit: osis_crypto::deposit_key(&dseed, &sync_id),
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
        let stamp = sign_stamp(&self.write, &self.sync_id, &osis_label::blob_id(&blob), &wrap, false);
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

fn cursor(b: u8) -> Cursor {
    Cursor::new(vec![b; 72]).expect("a short cursor")
}

/// A key actor's connection proof over the examples' challenge and static key.
pub fn proof(b: u8) -> ActorProof {
    let key = SigningSecret::from_seed(&s32(b));
    let record = CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [b; 32], account: false };
    Prover { key, record }.sign(false, &CHALLENGE, &STATIC_KEY)
}

/// A rotation's header-only copy as Prove carries it; its contents are the engine's to judge.
pub fn rotation() -> Value {
    Value::List(vec![Value::List(vec![Value::uint(1)]), Value::Enum(1, Some(Box::new(Value::Bytes(vec![0x52; 64])))), Value::List(vec![]), Value::List(vec![]), Value::List(vec![])])
}

/// `(name, message)` for every kind, in kind order, plus variants of the sum types.
pub fn messages() -> Vec<(&'static str, Msg)> {
    let f = Fixture::new(0x10);
    let l = f.sync_id;
    let other = SyncId([0x0b; 16]);
    let id = |b: u8| BlobId([b; 32]);
    let top = |n: u32| crate::limits::TOP_BIT | n;
    let entry = f.entry(Fixture::blob(1));
    let added = Event::Added { blob_id: osis_label::blob_id(&entry.blob), blob: Some(entry.blob.clone()), wrap: entry.wrap, stamp: Some(entry.stamp) };
    let entry_box = f.genesis_claims.entry_box(&l, &f.key_actor.verifying_key()).cloned().expect("the key actor is listed");
    let deposited = Fixture::blob(2);
    let dep_wrap = [0x78; WRAP_LEN];
    let dep_sig = osis_label::sign_deposit(&f.deposit, &l, &osis_label::blob_id(&deposited), &dep_wrap, false);
    let dk = osis_crypto::DeleteSecret::derive(&s32(0x7a));
    let open = |k: &SigningSecret| osis_crypto::sign_open(k, false, &l, &CHALLENGE, &STATIC_KEY);
    let gcs = crate::filter::encode_gcs(&[3, 200, 201, 511], 0);
    vec![
        ("error", Msg::Error { id: 1, code: Code::NOT_OPEN }),
        ("error answering an unreadable id", Msg::Error { id: 0, code: Code::MALFORMED }),
        ("ok", Msg::Ok { id: 2 }),
        ("ping", Msg::Ping { id: 3, wall_ms: 1_700_000_000_000 }),
        ("pong", Msg::Pong { id: 3, wall_ms: 1_700_000_000_123 }),
        ("register", Msg::Register { id: 7, sync_id: l, step: f.genesis.clone(), claim_set: Some(f.genesis_claims.clone()) }),
        ("register a child without its claim set", Msg::Register { id: 8, sync_id: l, step: f.child.clone(), claim_set: None }),
        ("status", Msg::Status { id: 14, codes: vec![Code::OK, Code::NOT_HEAD_KEY] }),
        ("delete", Msg::Delete { id: 14, sync_id: l, items: vec![DeleteItem::sign(&f.delete, &l, id(0xd1)), DeleteItem::sign_by(&f.sync, &[(2, &dk)], &[0x7d; 16], &[0x7e; 16], &l, id(0xd2)).expect("fixed delete")] }),
        ("fetch", Msg::Fetch { id: top(19), sync_id: l, max_reply: 32_768, ids: vec![id(0xb2), id(0xb5)] }),
        ("fetch reply", Msg::FetchReply { id: top(19), items: vec![Fetched { blob_id: id(0xb2), entry: Some((Fixture::blob(3), [0x79; WRAP_LEN], None)) }, Fetched { blob_id: id(0xb5), entry: None }] }),
        ("auth of a main session", Msg::Auth { id: 24, secret: None, session_id: [0x24; 16] }),
        ("auth of a client actor", Msg::Auth { id: 24, secret: Some(s32(0x25)), session_id: [0x24; 16] }),
        ("call", Msg::Call { id: 25, max_reply: 16_384, method: 3, args: vec![Value::Tid(Tid::from_bytes([0x25; 15])), Value::Str("t:reg.0".into())] }),
        ("reply", Msg::Reply { id: 25, outcome: Outcome::Ok { value: Value::uint(7) } }),
        ("reply with an error", Msg::Reply { id: 25, outcome: Outcome::Err { code: crate::ApiCode::PERMISSION, detail: vec![Value::Tid(Tid::from_bytes([0x26; 15])), Value::uint(1)] } }),
        ("sub", Msg::Sub { id: 27, max_reply: 65_536, filter: Value::List(vec![Value::uint(1)]) }),
        ("unsub", Msg::Unsub { id: 28, sub_id: 27 }),
        ("notify", Msg::Notify { sub_id: 27, payload: Payload::Delivery { value: Value::uint(9) } }),
        ("notify lapsed", Msg::Notify { sub_id: 27, payload: Payload::Lapsed }),
        ("notify too large", Msg::Notify { sub_id: 27, payload: Payload::TooLarge { source: Value::Str("t:reg.0".into()) } }),
        (
            "stranded",
            Msg::Stranded {
                id: 30,
                sync_id: l,
                holder: Tid::from_bytes([0x0d; 15]),
                keys: osis_label::HolderKeys { commits: vec![Value::List(vec![Value::List(vec![]), Value::Int(1), Value::List(vec![])])], records: vec![CreationRecord::Thing { admin: Tid::from_bytes([0x0e; 15]), nonce: [0x0f; 32], link: None }] },
            },
        ),
        ("suspect", Msg::Suspect { id: 31, sync_id: l, entries: vec![SuspectEntry { thing: Tid::from_bytes([0x0c; 15]), ak: osis_base::Ak::new("t:reg.0").expect("an AK"), digest: [0x0d; 16] }] }),
        ("prove", Msg::Prove { id: 32, proofs: vec![proof(0x32), proof(0x33)], rotations: None }),
        ("prove with rotations", Msg::Prove { id: 32, proofs: vec![proof(0x32)], rotations: Some(vec![rotation()]) }),
        ("proved", Msg::Proved { id: 32, proofs: vec![] }),
        ("resume", Msg::Resume { id: 34, nonce: [0x34; 32], tags: vec![[0x35; 32], [0x36; 32]] }),
        ("resumed", Msg::Resumed { id: 34, nonce: [0x37; 32], tag: Some([0x35; 32]) }),
        ("beacons", Msg::Beacons { id: top(36), generation: 1, base: None, f: 9, lo: 0, hi: 512, gcs, more: false }),
        ("beacons additions", Msg::Beacons { id: top(37), generation: 2, base: Some(1), f: 9, lo: 0, hi: 512, gcs: vec![], more: false }),
        ("offer", Msg::Offer { id: top(37), items: vec![OfferItem::Hit { hit: [9; 32], sig: None }, OfferItem::Hit { hit: [10; 32], sig: Some(open(&f.sync)) }, OfferItem::ByRole { sync_id: l, hits: vec![[8; 32]] }] }),
        ("offer with a deposit", Msg::Offer { id: top(38), items: vec![OfferItem::Deposit(DepositItem { sync_id: l, blob: deposited, wrap: dep_wrap, sig: dep_sig })] }),
        ("offer static", Msg::Offer { id: top(39), items: vec![OfferItem::Static { hit: [12; 32], signing_pk: f.key_actor.verifying_key().to_bytes(), sig: open(&f.key_actor) }] }),
        (
            "offer behind",
            Msg::Offer {
                id: top(40),
                items: vec![
                    OfferItem::Behind(BehindItem { sync_id: l, step: Some(f.genesis.id()), key: f.sync.verifying_key().to_bytes(), sig: open(&f.sync) }),
                    OfferItem::Behind(BehindItem { sync_id: l, step: None, key: f.sync.verifying_key().to_bytes(), sig: open(&f.sync) }),
                ],
            },
        ),
        ("lost", Msg::Lost { id: top(38), items: vec![(l, None), (other, Some(cursor(0x38)))] }),
        ("shared", Msg::Shared { id: top(37), items: vec![SharedItem { code: Code::OK, tag: Some([7; 32]), grant: None, sig: None }, SharedItem::code(Code::DECLINED)] }),
        (
            "shared with an entry grant",
            Msg::Shared { id: top(39), items: vec![SharedItem { code: Code::OK, tag: Some([7; 32]), grant: Some(Grant { entry_box: Some(entry_box), steps: vec![f.genesis.clone(), f.child.clone()] }), sig: Some(open(&f.sync)) }] },
        ),
        ("shared with a child step", Msg::Shared { id: top(40), items: vec![SharedItem { code: Code::OK, tag: None, grant: Some(Grant { entry_box: None, steps: vec![f.child.clone()] }), sig: None }, SharedItem::code(Code::UNKNOWN_SYNC_ID)] }),
        ("no record", Msg::NoRecord { id: crate::limits::NO_RECORD_ID }),
        ("pull", Msg::Pull(Box::new(Pull { id: top(41), cursor: Some(cursor(0x2c)), joins: vec![(l, None), (other, Some(cursor(0x2d)))], inline_limit: 0, max_reply: 65_536, follow: true, ephemeral: true }))),
        (
            "pull reply",
            Msg::PullReply(Box::new(PullReply { id: top(41), events: vec![(l, added.clone()), (l, Event::Deleted(id(0xb7))), (l, Event::Head(f.child.clone()))], cursor: Some(cursor(0x2e)), whole: false, trimmed: false, more: true, report: true, joins: vec![(other, Some(cursor(0x2f)))] })),
        ),
        ("stream", Msg::Stream(Box::new(Stream { events: vec![(l, added.clone())], cursor: Some(cursor(0x30)), report: true, seq: 3 }))),
        ("stream with no events", Msg::Stream(Box::new(Stream { events: vec![], cursor: Some(cursor(0x30)), report: true, seq: 0 }))),
        ("stream with no cursor", Msg::Stream(Box::new(Stream { events: vec![(l, Event::Full(true)), (l, Event::Refused(id(0xb1), Code::NOT_HEAD_KEY)), (l, added)], cursor: None, report: false, seq: 0 }))),
        ("applied", Msg::Applied { cursor: cursor(0x30) }),
        ("digest", Msg::Digest { digest: [0x31; 32] }),
        ("members", Msg::Members { sync_ids: vec![l, other], more: false }),
    ]
}

/// The body of `m` with item `i` of its top array replaced by `v` (`None`: removed).
fn with(m: &Msg, i: usize, v: Option<Value>) -> Vec<u8> {
    let Value::List(mut items) = m.to_value() else { return vec![] };
    match v {
        Some(v) => {
            if let Some(slot) = items.get_mut(i) {
                *slot = v;
            }
        }
        None => {
            items.remove(i);
        }
    }
    cbor::encode(&Value::List(items))
}

fn list(items: Vec<Value>) -> Value {
    Value::List(items)
}

fn bytes(n: usize, b: u8) -> Value {
    Value::Bytes(vec![b; n])
}

/// One rejected body per kind (and a few more): `(name, rule, body)`, `rule` naming the layout
/// rule of spec/wire.md §11 it breaks: `cbor`, `id`, `count`, `size`, `range`, `order`,
/// `shape`, `step`, `depth`.
pub fn rejections() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let ms: std::collections::BTreeMap<&str, Msg> = messages().into_iter().collect();
    let m = |n: &str| ms.get(n).cloned().expect("an example");
    let int = Value::uint;
    let deep = (0..70).fold(Value::uint(0), |v, _| list(vec![v]));
    let event_in = |name: &str, pos: usize, e: Value| {
        let Value::List(mut items) = m(name).to_value() else { return vec![] };
        if let Some(slot) = items.get_mut(pos) {
            *slot = list(vec![list(vec![bytes(16, 0x0a), e])]);
        }
        cbor::encode(&list(items))
    };
    vec![
        ("non-canonical id", "cbor", vec![0x82, 0x01, 0x18, 0x01]),
        ("trailing byte", "cbor", vec![0x82, 0x01, 0x01, 0x00]),
        ("indefinite array", "cbor", vec![0x9f, 0x01, 0x01, 0xff]),
        ("id at 2^32", "id", cbor::encode(&list(vec![int(2), int(1 << 32), int(0)]))),
        ("error with a field more", "shape", cbor::encode(&list(vec![int(0), int(1), int(8), int(0)]))),
        ("ok with id 0", "id", with(&m("ok"), 1, Some(int(0)))),
        ("ping with id 0", "id", with(&m("ping"), 1, Some(int(0)))),
        ("pong without wall_ms", "shape", with(&m("pong"), 2, None)),
        ("register with a sync ID of 15 bytes", "size", with(&m("register"), 2, Some(bytes(15, 1)))),
        ("register with a step that does not parse", "step", with(&m("register"), 3, Some(bytes(300, 0)))),
        ("status of no codes", "count", with(&m("status"), 2, Some(list(vec![])))),
        ("delete of no items", "count", with(&m("delete"), 3, Some(list(vec![])))),
        ("delete with levels descending", "order", with(&m("delete"), 3, Some(list(vec![list(vec![bytes(32, 1), list(vec![list(vec![int(2), bytes(64, 2)]), list(vec![int(1), bytes(64, 2)])]), bytes(64, 3)])])))),
        ("fetch with max_reply below SMALL_REPLY", "range", with(&m("fetch"), 3, Some(int(16_383)))),
        ("fetch reply with a stamp of 63 bytes", "size", with(&m("fetch reply"), 2, Some(list(vec![list(vec![bytes(32, 1), list(vec![list(vec![bytes(10, 0), bytes(57, 0), list(vec![bytes(63, 0)])])])])])))),
        ("auth with a secret of 31 bytes", "size", with(&m("auth of a client actor"), 2, Some(list(vec![bytes(31, 1)])))),
        ("call with a value 70 deep", "depth", with(&m("call"), 4, Some(list(vec![deep.clone()])))),
        ("reply with an unknown outcome", "shape", with(&m("reply"), 2, Some(list(vec![int(2), int(0)])))),
        ("sub with max_reply above REPLY_BUDGET", "range", with(&m("sub"), 2, Some(int(crate::limits::REPLY_BUDGET as u64 + 1)))),
        ("unsub of subscription 0", "id", with(&m("unsub"), 2, Some(int(0)))),
        ("notify with an id", "id", with(&m("notify"), 1, Some(int(27)))),
        ("stranded with a holder as a tid value", "size", with(&m("stranded"), 3, Some(Value::Tid(Tid::from_bytes([0x0d; 15]))))),
        ("suspect with a digest of 32 bytes", "size", with(&m("suspect"), 3, Some(list(vec![list(vec![bytes(15, 0x0c), Value::Str("t:reg.0".into()), bytes(32, 0)])])))),
        ("prove with a key of 31 bytes", "size", with(&m("prove"), 2, Some(list(vec![list(vec![proof(1).record.to_value(), bytes(31, 0), bytes(64, 0)])])))),
        ("prove with a rotation carrying a section", "shape", with(&m("prove with rotations"), 3, Some(list(vec![list(vec![list(vec![]), list(vec![]), list(vec![]), list(vec![]), list(vec![list(vec![])])])])))),
        ("proved as a push", "id", with(&m("proved"), 1, Some(int(0)))),
        ("resume with a tag of 31 bytes", "size", with(&m("resume"), 3, Some(list(vec![bytes(31, 0)])))),
        ("resumed with two tags", "shape", with(&m("resumed"), 3, Some(list(vec![bytes(32, 0), bytes(32, 0)])))),
        ("beacons without the top bit", "id", with(&m("beacons"), 1, Some(int(36)))),
        ("beacons of width 31", "range", with(&m("beacons"), 4, Some(int(31)))),
        ("beacons with a value past hi", "range", with(&m("beacons"), 6, Some(int(300)))),
        ("beacons with a zero byte of padding", "shape", with(&m("beacons additions"), 7, Some(bytes(1, 0)))),
        ("offer of no items", "count", with(&m("offer"), 2, Some(list(vec![])))),
        ("offer deposit with a wrap of 48 bytes", "size", with(&m("offer"), 2, Some(list(vec![list(vec![int(2), bytes(16, 1), bytes(1, 1), bytes(48, 0), bytes(64, 0)])])))),
        ("offer of an unknown item", "shape", with(&m("offer"), 2, Some(list(vec![list(vec![int(5), bytes(32, 1)])])))),
        ("lost with a cursor of 257 bytes", "size", with(&m("lost"), 2, Some(list(vec![list(vec![bytes(16, 1), list(vec![bytes(257, 0)])])])))),
        ("shared refusal carrying a tag", "shape", with(&m("shared"), 2, Some(list(vec![list(vec![int(14), list(vec![bytes(32, 0)]), list(vec![]), list(vec![])])])))),
        ("shared with a sig and no tag", "shape", with(&m("shared"), 2, Some(list(vec![list(vec![int(0), list(vec![]), list(vec![]), list(vec![bytes(64, 0)])])])))),
        ("no record with another id", "id", with(&m("no record"), 1, Some(int(u64::from(crate::limits::TOP_BIT | 1))))),
        ("pull with max_reply 0", "range", with(&m("pull"), 6, Some(int(0)))),
        ("pull reply with a full event", "shape", event_in("pull reply", 2, list(vec![int(2), Value::Bool(true)]))),
        ("stream with a cursor and a refused event", "shape", event_in("stream", 2, list(vec![int(4), bytes(32, 1), int(9)]))),
        ("stream with no cursor and a seq", "shape", with(&m("stream with no cursor"), 5, Some(int(1)))),
        ("stream refusing for room", "shape", event_in("stream with no cursor", 2, list(vec![int(4), bytes(32, 1), int(12)]))),
        ("applied with a cursor of 257 bytes", "size", with(&m("applied"), 2, Some(bytes(257, 0)))),
        ("digest of 31 bytes", "size", with(&m("digest"), 2, Some(bytes(31, 0)))),
        ("members with a sync ID of 17 bytes", "size", with(&m("members"), 2, Some(list(vec![bytes(17, 0)])))),
    ]
}
