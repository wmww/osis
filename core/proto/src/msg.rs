//! Protocol version 1 messages (spec/wire.md §11.2) with their caps and decoder limits (§13).
//! Steps, claim sets, delete items and holder keys are osis-label's types; the wire carries
//! steps, claim sets and entry boxes as their canonical bytes in byte strings. Decoding takes
//! only canonical CBOR (spec/data-model.md §5) in each kind's exact layout, so whatever decodes
//! re-encodes to the bytes it came from.

use crate::Error;
use crate::api::{Outcome, Payload, value};
use crate::dec::{self, Fields};
use crate::limits::*;
use crate::{ActorProof, SyncId};
use osis_base::{Ak, BlobId, Limits, Tid, Value, cbor};
pub use osis_crypto::Signature;
pub use osis_label::{ClaimSet, DeleteItem, HolderKeys, Step, StepId};
use osis_schema::Codec;
use std::cell::Cell;
pub use osis_schema::core_types::SecretBox;

pub const WRAP_LEN: usize = osis_crypto::WRAP_LEN;
/// A wrap: 57 bytes (spec/wire.md §5).
pub type Wrap = [u8; WRAP_LEN];
/// A stamp: a raw Ed25519 signature by the head's write key (spec/wire.md §11.2 Stamp).
pub type Stamp = Signature;
/// A request id, below 2^32 (spec/wire.md §11.1).
pub type Id = u32;

/// Status codes (spec/wire.md §11.2). An Error or a Shared may carry a code this build does not
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(pub u64);

impl Code {
    pub const OK: Code = Code(0);
    /// Refused: a signature or credential that does not stand (Register 1, Delete 1, Auth).
    pub const REFUSED: Code = Code(1);
    pub const MALFORMED: Code = Code(2);
    /// A relay-only blob above `MAX_RELAY_BLOB`.
    pub const TOO_LARGE: Code = Code(3);
    pub const RATE_LIMITED: Code = Code(4);
    pub const DEPOSIT_BUDGET_FULL: Code = Code(5);
    pub const TOMBSTONED: Code = Code(6);
    pub const EXPIRED: Code = Code(7);
    pub const NOT_OPEN: Code = Code(8);
    /// A signature under an earlier key of the sync ID's role.
    pub const NOT_HEAD_KEY: Code = Code(9);
    pub const UNSUPPORTED: Code = Code(11);
    pub const STORAGE_CAP: Code = Code(12);
    pub const UNKNOWN_SYNC_ID: Code = Code(13);
    /// Refused for no stated reason (an Offer item, a Register of a sync ID the node reads or
    /// does not sync, a shared-set request with no shared set kept).
    pub const DECLINED: Code = Code(14);
}

/// A node-log cursor: at most `MAX_CURSOR_BYTES` opaque bytes the answering node sealed
/// (spec/wire.md §11.2 Pull).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor(Vec<u8>);

impl Cursor {
    pub fn new(bytes: Vec<u8>) -> Result<Cursor, Error> {
        if bytes.len() > MAX_CURSOR_BYTES {
            return Err(Error::Cap("cursor"));
        }
        Ok(Cursor(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// `event := [0, blob_id, Opt(blob), wrap, Opt(stamp)] | [1, blob_id] | [2, full] | [3, step] |
/// [4, blob_id, code]` (spec/wire.md §11.2 Events).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // a step carries parsed keys; boxing buys nothing here
pub enum Event {
    /// An entry added, or a deposited one stamped: its wrap and stamp replaced. No stamp:
    /// deposited.
    Added { blob_id: BlobId, blob: Option<Vec<u8>>, wrap: Wrap, stamp: Option<Stamp> },
    Deleted(BlobId),
    /// The sender is full for the sync ID (true) or has room again (false). Only in a Stream
    /// with no cursor.
    Full(bool),
    /// A new head, without claim set.
    Head(Step),
    /// The sender refused a pulled entry for anything but room, with the refusal's code. Only
    /// in a Stream with no cursor.
    Refused(BlobId, Code),
}

/// A FetchReply item: the entry of the blob ID, or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    pub blob_id: BlobId,
    /// `[blob, wrap, Opt(stamp)]`.
    pub entry: Option<(Vec<u8>, Wrap, Option<Stamp>)>,
}

/// A member entering a Pull's stream from its own cursor, or (none) the start; in a PullReply,
/// a join still in pages at its cursor or (none) one the server does not share. A Lost item has
/// the same shape: the sync ID and where it stopped for the receiver.
pub type Join = (SyncId, Option<Cursor>);

/// `Pull [41, id, Opt(cursor), [join*], inline_limit, max_reply, follow, ephemeral]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pull {
    pub id: Id,
    pub cursor: Option<Cursor>,
    pub joins: Vec<Join>,
    pub inline_limit: u64,
    pub max_reply: u64,
    pub follow: bool,
    pub ephemeral: bool,
}

/// `PullReply [42, id, [[sync_id, event]*], Opt(cursor), whole, trimmed, more, report, [join*]]`:
/// `trimmed` (with `whole`): a cursor the Pull named is on this store's history below its
/// deletion horizon, so deletions since it are not all in the log. `joins` are the Pull's joins
/// not in the stream at `cursor`: still in pages at their own cursor, or (none) not shared here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullReply {
    pub id: Id,
    pub events: Vec<(SyncId, Event)>,
    pub cursor: Option<Cursor>,
    pub whole: bool,
    pub trimmed: bool,
    pub more: bool,
    pub report: bool,
    pub joins: Vec<Join>,
}

/// `Stream [43, 0, [[sync_id, event]*], Opt(cursor), report, seq]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub events: Vec<(SyncId, Event)>,
    pub cursor: Option<Cursor>,
    pub report: bool,
    /// Streams with a cursor the server sent on the connection since its last PullReply; 0 in
    /// one without a cursor.
    pub seq: u64,
}

/// A Deposit item `[2, sync_id, blob, wrap, sig]` (spec/wire.md §11.2 Offer, Deposit item).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositItem {
    pub sync_id: SyncId,
    pub blob: Vec<u8>,
    pub wrap: Wrap,
    /// By the deposit key under `"osis v1 deposit"` (`"osis v1 role entry"` for a role entry).
    pub sig: Signature,
}

/// A Behind item `[3, sync_id, Opt(step_id), key, sig]` (spec/wire.md §11.2 Offer,
/// spec/sync-ids.md §6): a credential key of the step it names (none: by a sync key or a key
/// actor's signing key) and an open signature by it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BehindItem {
    pub sync_id: SyncId,
    pub step: Option<StepId>,
    pub key: [u8; 32],
    pub sig: Signature,
}

/// `item := [0, hit, Opt(sig)] | [1, sync_id, [hit*]] | [2, ...] | [3, ...] | [4, hit, signing_pk, sig]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferItem {
    /// A Hit with the open signature proving its credential, where it needs one.
    Hit { hit: [u8; 32], sig: Option<Signature> },
    /// A sync ID the sender judged the peer reads, with the sender's Hits.
    ByRole { sync_id: SyncId, hits: Vec<[u8; 32]> },
    Deposit(DepositItem),
    Behind(BehindItem),
    /// A Hit on a key actor's static entry with its signing key and an open signature by it.
    Static { hit: [u8; 32], signing_pk: [u8; 32], sig: Signature },
}

/// `grant := [Opt(entry_box), [step+]]`: the head's entry box for a static entry and the path to
/// that head, or the steps after a Behind item's (each without claim set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub entry_box: Option<SecretBox>,
    pub steps: Vec<Step>,
}

/// One answer of a Shared: `[code, Opt(tag), Opt(grant), Opt(sig)]`. Only code 0 carries
/// anything, and a `sig` only beside a tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedItem {
    pub code: Code,
    pub tag: Option<[u8; 32]>,
    pub grant: Option<Grant>,
    /// An open signature by the sync key of the replier's step.
    pub sig: Option<Signature>,
}

impl SharedItem {
    /// An answer carrying its code alone.
    pub fn code(code: Code) -> SharedItem {
        SharedItem { code, tag: None, grant: None, sig: None }
    }
}

/// `suspect := [thing, ak, digest]` (spec/wire.md §11.2 Stranded and Suspect).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuspectEntry {
    pub thing: Tid,
    pub ak: Ak,
    pub digest: [u8; SUSPECT_DIGEST_LEN],
}

/// `ditem` is osis-label's `DeleteItem`; `actor_proof` is `ActorProof`.
/// Every message after Hello (spec/wire.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // a Register's step carries parsed keys; one per message
pub enum Msg {
    Error { id: Id, code: Code },
    Ok { id: Id },
    Ping { id: Id, wall_ms: u64 },
    Pong { id: Id, wall_ms: u64 },
    Register { id: Id, sync_id: SyncId, step: Step, claim_set: Option<ClaimSet> },
    /// One code per item of a Delete, in order.
    Status { id: Id, codes: Vec<Code> },
    Delete { id: Id, sync_id: SyncId, items: Vec<DeleteItem> },
    Fetch { id: Id, sync_id: SyncId, max_reply: u64, ids: Vec<BlobId> },
    FetchReply { id: Id, items: Vec<Fetched> },
    /// A main session sends no secret; a client-actor session its bearer secret.
    Auth { id: Id, secret: Option<osis_crypto::Secret32>, session_id: [u8; SESSION_ID_LEN] },
    Call { id: Id, max_reply: u64, method: u64, args: Vec<Value> },
    Reply { id: Id, outcome: Outcome },
    /// The id names the subscription.
    Sub { id: Id, max_reply: u64, filter: Value },
    Unsub { id: Id, sub_id: Id },
    Notify { sub_id: Id, payload: Payload },
    /// A sync ID the sender is stranded on, the holder it reads the sync ID's actor through and
    /// that holder's holder keys (spec/wire.md §9).
    Stranded { id: Id, sync_id: SyncId, holder: Tid, keys: HolderKeys },
    Suspect { id: Id, sync_id: SyncId, entries: Vec<SuspectEntry> },
    /// `rotations`: the account's signed rotations the verifier may lack, as header-only copies
    /// (spec/sync-opens.md §2), each a `CommitBlobPlaintext` value the engine judges.
    Prove { id: Id, proofs: Vec<ActorProof>, rotations: Option<Vec<Value>> },
    Proved { id: Id, proofs: Vec<ActorProof> },
    Resume { id: Id, nonce: [u8; 32], tags: Vec<[u8; 32]> },
    Resumed { id: Id, nonce: [u8; 32], tag: Option<[u8; 32]> },
    /// One page of generation `generation` of a side's filter; `base` present: additions to it.
    Beacons { id: Id, generation: u64, base: Option<u64>, f: u8, lo: u64, hi: u64, gcs: Vec<u8>, more: bool },
    Offer { id: Id, items: Vec<OfferItem> },
    Lost { id: Id, items: Vec<Join> },
    Shared { id: Id, items: Vec<SharedItem> },
    NoRecord { id: Id },
    Pull(Box<Pull>),
    PullReply(Box<PullReply>),
    Stream(Box<Stream>),
    Applied { cursor: Cursor },
    Digest { digest: [u8; 32] },
    Members { sync_ids: Vec<SyncId>, more: bool },
}

/// How a kind travels (spec/wire.md §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Sent with a fresh nonzero id; the other side answers it.
    Request,
    /// Carries the id of the request it answers (Error: 0 for a frame whose id could not be read).
    Reply,
    /// Id 0, never answered.
    Push,
}

/// The flow of a kind version 1 knows, `None` for any other (a retired kind included).
pub fn flow(kind: u64) -> Option<Flow> {
    Some(match kind {
        2 | 7 | 14 | 19 | 24 | 25 | 27 | 28 | 30 | 31 | 32 | 34 | 36 | 37 | 38 | 40 | 41 => Flow::Request,
        0 | 1 | 3 | 11 | 20 | 26 | 33 | 35 | 39 | 42 => Flow::Reply,
        29 | 43 | 44 | 45 | 46 => Flow::Push,
        _ => return None,
    })
}

/// Whether a message of kind `reply` answers a request of kind `request` (spec/wire.md §11.2):
/// an Error answers any request; any other reply kind only its own requests.
pub fn answers(request: u64, reply: u64) -> bool {
    reply == 0
        || match request {
            2 => reply == 3,
            7 | 28 | 30 | 31 => reply == 1,
            14 => reply == 11,
            19 => reply == 20,
            24 | 25 | 27 => reply == 26,
            32 => reply == 33,
            34 => reply == 35,
            36 | 37 | 38 | 40 => reply == 39,
            41 => reply == 42,
            _ => false,
        }
}

/// Kinds whose id has its top bit set: the shared set's and the stream's requests and their
/// answers, Fetch and FetchReply among them (spec/wire.md §11.2 Shared-set request ids).
fn top_bit_kind(kind: u64) -> bool {
    matches!(kind, 19 | 20 | 36..=42)
}

/// A frame body that is not a valid message: its kind and request id when readable (`read`;
/// else 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub kind: u64,
    pub id: Id,
    /// Whether `kind` and `id` were read: a frame whose id cannot be read is answered by an
    /// Error with id 0, whatever it was meant to be (spec/wire.md §11.1).
    pub read: bool,
    pub error: Error,
}

impl Rejected {
    /// The Error code that answers it: 11 for an unknown kind, else 2.
    pub fn code(&self) -> Code {
        match self.error {
            Error::UnknownKind(_) => Code::UNSUPPORTED,
            _ => Code::MALFORMED,
        }
    }

    /// Whether it is answered: a malformed request, a frame of unknown kind or one whose id
    /// cannot be read is answered by Error (with its id, or 0); a malformed reply or push is
    /// dropped (spec/wire.md §11.1).
    pub fn answered(&self) -> bool {
        !self.read || matches!(self.error, Error::UnknownKind(_)) || flow(self.kind).is_none_or(|f| f == Flow::Request)
    }
}

/// The kind and id at the start of a frame body, when they are there (a frame still arriving);
/// `Msg::decode` checks the whole once it is in.
pub fn peek_head(body: &[u8]) -> Option<(u64, Id)> {
    fn uint(b: &[u8]) -> Option<(u64, &[u8])> {
        let (&ib, rest) = b.split_first()?;
        let n = match ib {
            0..=23 => return Some((u64::from(ib), rest)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return None,
        };
        let (x, rest) = rest.split_at_checked(n)?;
        Some((x.iter().fold(0, |a, b| a << 8 | u64::from(*b)), rest))
    }
    let (&ib, rest) = body.split_first()?;
    // an array of at most 23 items: every v1 message
    if !(0x82..=0x97).contains(&ib) {
        return None;
    }
    let (kind, rest) = uint(rest)?;
    let (id, _) = uint(rest)?;
    Some((kind, Id::try_from(id).ok()?))
}

impl Msg {
    pub fn kind(&self) -> u64 {
        use Msg::*;
        match self {
            Error { .. } => 0,
            Ok { .. } => 1,
            Ping { .. } => 2,
            Pong { .. } => 3,
            Register { .. } => 7,
            Status { .. } => 11,
            Delete { .. } => 14,
            Fetch { .. } => 19,
            FetchReply { .. } => 20,
            Auth { .. } => 24,
            Call { .. } => 25,
            Reply { .. } => 26,
            Sub { .. } => 27,
            Unsub { .. } => 28,
            Notify { .. } => 29,
            Stranded { .. } => 30,
            Suspect { .. } => 31,
            Prove { .. } => 32,
            Proved { .. } => 33,
            Resume { .. } => 34,
            Resumed { .. } => 35,
            Beacons { .. } => 36,
            Offer { .. } => 37,
            Lost { .. } => 38,
            Shared { .. } => 39,
            NoRecord { .. } => 40,
            Pull(_) => 41,
            PullReply(_) => 42,
            Stream(_) => 43,
            Applied { .. } => 44,
            Digest { .. } => 45,
            Members { .. } => 46,
        }
    }

    /// The request id (0 in a push).
    pub fn id(&self) -> Id {
        use Msg::*;
        match self {
            Error { id, .. } | Ok { id } | Ping { id, .. } | Pong { id, .. } | Register { id, .. } | Status { id, .. } | Delete { id, .. } | Fetch { id, .. } | FetchReply { id, .. } | Auth { id, .. } | Call { id, .. } | Reply { id, .. } | Sub { id, .. } | Unsub { id, .. } | Stranded { id, .. } | Suspect { id, .. } | Prove { id, .. } | Proved { id, .. } | Resume { id, .. } | Resumed { id, .. } | Beacons { id, .. } | Offer { id, .. } | Lost { id, .. } | Shared { id, .. } | NoRecord { id } => *id,
            Pull(p) => p.id,
            PullReply(r) => r.id,
            Notify { .. } | Stream(_) | Applied { .. } | Digest { .. } | Members { .. } => 0,
        }
    }

    pub fn flow(&self) -> Flow {
        flow(self.kind()).unwrap_or(Flow::Push)
    }

    /// Sets the request id (a request's, or the one a reply answers); a push keeps id 0.
    pub fn set_id(&mut self, new: Id) {
        use Msg::*;
        match self {
            Error { id, .. } | Ok { id } | Ping { id, .. } | Pong { id, .. } | Register { id, .. } | Status { id, .. } | Delete { id, .. } | Fetch { id, .. } | FetchReply { id, .. } | Auth { id, .. } | Call { id, .. } | Reply { id, .. } | Sub { id, .. } | Unsub { id, .. } | Stranded { id, .. } | Suspect { id, .. } | Prove { id, .. } | Proved { id, .. } | Resume { id, .. } | Resumed { id, .. } | Beacons { id, .. } | Offer { id, .. } | Lost { id, .. } | Shared { id, .. } | NoRecord { id } => *id = new,
            Pull(p) => p.id = new,
            PullReply(r) => r.id = new,
            Notify { .. } | Stream(_) | Applied { .. } | Digest { .. } | Members { .. } => {}
        }
    }

    pub fn to_value(&self) -> Value {
        use Msg as M;
        let k = Value::uint(self.kind());
        let id = Value::uint(u64::from(self.id()));
        let s = |x: &SyncId| Value::bytes(&x.0);
        let items = match self {
            M::Error { code, .. } => vec![k, id, Value::uint(code.0)],
            M::Ok { .. } | M::NoRecord { .. } => vec![k, id],
            M::Ping { wall_ms, .. } | M::Pong { wall_ms, .. } => vec![k, id, Value::uint(*wall_ms)],
            M::Register { sync_id, step, claim_set, .. } => vec![k, id, s(sync_id), step_value(step), Value::opt(claim_set.as_ref().map(|c| Value::Bytes(c.to_bytes())))],
            M::Status { codes, .. } => vec![k, id, Value::List(codes.iter().map(|c| Value::uint(c.0)).collect())],
            M::Delete { sync_id, items, .. } => vec![k, id, s(sync_id), Value::List(items.iter().map(DeleteItem::to_value).collect())],
            M::Fetch { sync_id, max_reply, ids, .. } => vec![k, id, s(sync_id), Value::uint(*max_reply), Value::List(ids.iter().map(|i| Value::bytes(&i.0)).collect())],
            M::FetchReply { items, .. } => vec![k, id, Value::List(items.iter().map(fetched_value).collect())],
            M::Auth { secret, session_id, .. } => vec![k, id, Value::opt(secret.as_ref().map(|s| Value::bytes(s.expose()))), Value::bytes(session_id)],
            M::Call { max_reply, method, args, .. } => vec![k, id, Value::uint(*max_reply), Value::uint(*method), Value::List(args.clone())],
            M::Reply { outcome, .. } => vec![k, id, outcome.to_value()],
            M::Sub { max_reply, filter, .. } => vec![k, id, Value::uint(*max_reply), filter.clone()],
            M::Unsub { sub_id, .. } => vec![k, id, Value::uint(u64::from(*sub_id))],
            M::Notify { sub_id, payload } => vec![k, id, Value::uint(u64::from(*sub_id)), payload.to_value()],
            M::Stranded { sync_id, holder, keys, .. } => {
                let [commits, records] = keys.to_values();
                vec![k, id, s(sync_id), Value::bytes(holder.as_bytes()), commits, records]
            }
            M::Suspect { sync_id, entries, .. } => vec![k, id, s(sync_id), Value::List(entries.iter().map(|e| Value::List(vec![Value::bytes(e.thing.as_bytes()), Value::Str(e.ak.as_str().to_string()), Value::bytes(&e.digest)])).collect())],
            M::Prove { proofs, rotations, .. } => vec![k, id, proofs_value(proofs), Value::opt(rotations.as_ref().map(|r| Value::List(r.clone())))],
            M::Proved { proofs, .. } => vec![k, id, proofs_value(proofs)],
            M::Resume { nonce, tags, .. } => vec![k, id, Value::bytes(nonce), Value::List(tags.iter().map(|t| Value::bytes(t)).collect())],
            M::Resumed { nonce, tag, .. } => vec![k, id, Value::bytes(nonce), Value::opt(tag.as_ref().map(|t| Value::bytes(t)))],
            M::Beacons { generation, base, f, lo, hi, gcs, more, .. } => vec![k, id, Value::uint(*generation), Value::opt(base.map(Value::uint)), Value::uint(u64::from(*f)), Value::uint(*lo), Value::uint(*hi), Value::bytes(gcs), Value::Bool(*more)],
            M::Offer { items, .. } => vec![k, id, Value::List(items.iter().map(offer_item_value).collect())],
            M::Lost { items, .. } => vec![k, id, joins_value(items)],
            M::Shared { items, .. } => vec![k, id, Value::List(items.iter().map(shared_item_value).collect())],
            M::Pull(p) => vec![k, id, opt_cursor(&p.cursor), joins_value(&p.joins), Value::uint(p.inline_limit), Value::uint(p.max_reply), Value::Bool(p.follow), Value::Bool(p.ephemeral)],
            M::PullReply(r) => vec![k, id, events_value(&r.events), opt_cursor(&r.cursor), Value::Bool(r.whole), Value::Bool(r.trimmed), Value::Bool(r.more), Value::Bool(r.report), joins_value(&r.joins)],
            M::Stream(st) => vec![k, id, events_value(&st.events), opt_cursor(&st.cursor), Value::Bool(st.report), Value::uint(st.seq)],
            M::Applied { cursor } => vec![k, id, Value::bytes(cursor.as_bytes())],
            M::Digest { digest } => vec![k, id, Value::bytes(digest)],
            M::Members { sync_ids, more } => vec![k, id, Value::List(sync_ids.iter().map(s).collect()), Value::Bool(*more)],
        };
        Value::List(items)
    }

    /// The frame body. The sender keeps it within `MAX_MESSAGE` (it pages).
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// Decodes a frame body, enforcing every layout rule and cap of spec/wire.md §11.2 and the
    /// limits of §13. Memory: items are counted before they are built, those of the canonical
    /// bytes a byte string carries (steps, claim sets, entry boxes) included, so a message builds
    /// at most `MAX_MESSAGE_ITEMS` values in all beside its bytes.
    pub fn decode(body: &[u8]) -> Result<Msg, Rejected> {
        // a body that is not canonical CBOR may still show its kind and id
        let bad = |error: Error| match peek_head(body) {
            Some((kind, id)) => Rejected { kind, id, read: true, error },
            None => Rejected { kind: 0, id: 0, read: false, error },
        };
        let limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_MESSAGE };
        let mut items = 0usize;
        cbor::visit_items(body, &limits, &mut |_, _, _| items += 1).map_err(|e| bad(e.into()))?;
        if items > MAX_MESSAGE_ITEMS {
            return Err(bad(Error::Cap("message items")));
        }
        let v = cbor::decode(body, &limits).map_err(|e| bad(e.into()))?;
        let (kind, id) = match &v {
            Value::List(items) => match (items.first().and_then(Value::as_uint), items.get(1).and_then(Value::as_uint)) {
                (Some(k), Some(i)) if i <= MAX_ID => (k, i as Id),
                _ => return Err(Rejected { kind: 0, id: 0, read: false, error: Error::Malformed("message head") }),
            },
            _ => return Err(Rejected { kind: 0, id: 0, read: false, error: Error::Malformed("message head") }),
        };
        decode_body(kind, id, v, &Items(Cell::new(MAX_MESSAGE_ITEMS - items))).map_err(|error| Rejected { kind, id, read: true, error })
    }
}

/// The CBOR items a message may still build (spec/wire.md §13: at most `MAX_MESSAGE_ITEMS` in
/// all): canonical bytes carried in a byte string are counted against it before they are decoded.
struct Items(Cell<usize>);

impl Items {
    /// `bytes` decoded at `depth`, once its items fit what is left.
    fn decode(&self, bytes: &[u8], depth: usize) -> Result<Value, Error> {
        let limits = Limits { max_depth: depth, max_bytes: MAX_MESSAGE };
        let mut n = 0usize;
        cbor::visit_items(bytes, &limits, &mut |_, _, _| n += 1)?;
        let left = self.0.get().checked_sub(n).ok_or(Error::Cap("message items"))?;
        self.0.set(left);
        Ok(cbor::decode(bytes, &limits)?)
    }
}

/// The id rules of spec/wire.md §11.1 and §11.2 (Shared-set request ids, NoRecord).
fn check_id(kind: u64, id: Id) -> Result<(), Error> {
    let ok = match flow(kind) {
        None => return Err(Error::UnknownKind(kind)),
        Some(Flow::Push) => id == 0,
        Some(Flow::Reply) if kind == 0 => true,
        Some(_) => id != 0 && (!top_bit_kind(kind) || id & TOP_BIT != 0) && (kind != 40 || id == NO_RECORD_ID),
    };
    if ok { Ok(()) } else { Err(Error::Malformed("id")) }
}

fn decode_body(kind: u64, id: Id, v: Value, n: &Items) -> Result<Msg, Error> {
    check_id(kind, id)?;
    let mut f = Fields::range(v, 2, usize::MAX, "message")?;
    f.next()?;
    f.next()?;
    let msg = match kind {
        0 => Msg::Error { id, code: Code(f.uint()?) },
        1 => Msg::Ok { id },
        2 => Msg::Ping { id, wall_ms: f.uint()? },
        3 => Msg::Pong { id, wall_ms: f.uint()? },
        7 => Msg::Register { id, sync_id: sync_id(&mut f)?, step: step(f.next()?, n)?, claim_set: f.opt()?.map(|v| claim_set(v, n)).transpose()? },
        11 => Msg::Status { id, codes: f.list(1, MAX_DELETE_ITEMS, "status codes")?.into_iter().map(|v| dec::uint(v, "code").map(Code)).collect::<Result<_, _>>()? },
        14 => {
            let sync_id = sync_id(&mut f)?;
            let items = f.list(1, MAX_DELETE_ITEMS, "delete items")?.iter().map(DeleteItem::from_value).collect::<Result<_, _>>()?;
            Msg::Delete { id, sync_id, items }
        }
        19 => Msg::Fetch { id, sync_id: sync_id(&mut f)?, max_reply: max_reply(&mut f)?, ids: f.list(1, MAX_FETCH_IDS, "fetch ids")?.into_iter().map(|v| dec::fixed(v, "blob id").map(BlobId)).collect::<Result<_, _>>()? },
        20 => Msg::FetchReply { id, items: f.list(0, MAX_FETCH_IDS, "fetch items")?.into_iter().map(fetched).collect::<Result<_, _>>()? },
        24 => Msg::Auth { id, secret: f.opt()?.map(|v| dec::fixed::<CLIENT_SECRET_LEN>(v, "client secret").map(osis_crypto::Secret32::from_bytes)).transpose()?, session_id: f.fixed()? },
        25 => Msg::Call { id, max_reply: max_reply(&mut f)?, method: f.uint()?, args: f.list(0, usize::MAX, "args")?.into_iter().map(value).collect::<Result<_, _>>()? },
        26 => Msg::Reply { id, outcome: Outcome::from_value(f.next()?)? },
        27 => Msg::Sub { id, max_reply: max_reply(&mut f)?, filter: value(f.next()?)? },
        28 => Msg::Unsub { id, sub_id: sub_id(&mut f)? },
        29 => Msg::Notify { sub_id: sub_id(&mut f)?, payload: Payload::from_value(f.next()?)? },
        30 => {
            let sync_id = sync_id(&mut f)?;
            let holder = Tid::from_bytes(f.fixed()?);
            let (commits, records) = (f.next()?, f.next()?);
            Msg::Stranded { id, sync_id, holder, keys: HolderKeys::from_values(&commits, &records)? }
        }
        31 => Msg::Suspect { id, sync_id: sync_id(&mut f)?, entries: f.list(1, usize::MAX, "suspect entries")?.into_iter().map(suspect_entry).collect::<Result<_, _>>()? },
        32 => Msg::Prove { id, proofs: proofs(&mut f)?, rotations: f.opt()?.map(rotations).transpose()? },
        33 => Msg::Proved { id, proofs: proofs(&mut f)? },
        34 => Msg::Resume { id, nonce: f.fixed()?, tags: f.list(0, MAX_RESUME_TAGS, "resume tags")?.into_iter().map(|v| dec::fixed(v, "tag")).collect::<Result<_, _>>()? },
        35 => Msg::Resumed { id, nonce: f.fixed()?, tag: f.opt()?.map(|v| dec::fixed(v, "tag")).transpose()? },
        36 => beacons(id, &mut f)?,
        37 => Msg::Offer { id, items: f.list(1, MAX_OFFER_ITEMS, "offer items")?.into_iter().map(offer_item).collect::<Result<_, _>>()? },
        38 => Msg::Lost { id, items: joins(f.list(1, MAX_OFFER_ITEMS, "lost items")?)? },
        39 => Msg::Shared { id, items: f.list(1, MAX_OFFER_ITEMS, "shared items")?.into_iter().map(|v| shared_item(v, n)).collect::<Result<_, _>>()? },
        40 => Msg::NoRecord { id },
        41 => Msg::Pull(Box::new(Pull {
            id,
            cursor: opt_cursor_of(&mut f)?,
            joins: joins(f.list(0, usize::MAX, "joins")?)?,
            inline_limit: f.uint()?,
            max_reply: max_reply(&mut f)?,
            follow: f.bool()?,
            ephemeral: f.bool()?,
        })),
        42 => {
            let events = events(f.list(0, usize::MAX, "events")?, n)?;
            if events.iter().any(|(_, e)| cursorless_only(e)) {
                return Err(Error::Malformed("full or refused event outside a Stream with no cursor"));
            }
            Msg::PullReply(Box::new(PullReply { id, events, cursor: opt_cursor_of(&mut f)?, whole: f.bool()?, trimmed: f.bool()?, more: f.bool()?, report: f.bool()?, joins: joins(f.list(0, usize::MAX, "joins")?)? }))
        }
        43 => {
            let st = Stream { events: events(f.list(0, usize::MAX, "events")?, n)?, cursor: opt_cursor_of(&mut f)?, report: f.bool()?, seq: f.uint()? };
            let ok = match st.cursor {
                Some(_) => !st.events.iter().any(|(_, e)| cursorless_only(e)),
                None => st.seq == 0 && !st.report,
            };
            if !ok {
                return Err(Error::Malformed("stream"));
            }
            Msg::Stream(Box::new(st))
        }
        44 => Msg::Applied { cursor: Cursor::new(f.bytes(MAX_CURSOR_BYTES)?)? },
        45 => Msg::Digest { digest: f.fixed()? },
        46 => Msg::Members { sync_ids: f.list(0, MAX_MEMBERS, "members")?.into_iter().map(|v| dec::fixed(v, "sync id").map(SyncId)).collect::<Result<_, _>>()?, more: f.bool()? },
        _ => return Err(Error::UnknownKind(kind)),
    };
    f.end()?;
    Ok(msg)
}

/// Events only a Stream with no cursor carries (spec/wire.md §11.2 Events).
fn cursorless_only(e: &Event) -> bool {
    matches!(e, Event::Full(_) | Event::Refused(..))
}

/// `Beacons [36, id, generation, Opt(base), f, lo, hi, gcs, more]`: a width a filter of at most
/// `MAX_FILTER_ENTRIES` can have, a range inside `[0, 2^f)`, and a page that decodes inside it
/// (spec/wire.md §11.2 Beacons). The order of pages and the entry counts are the receiver's to
/// check across pages.
fn beacons(id: Id, f: &mut Fields) -> Result<Msg, Error> {
    let generation = f.uint()?;
    let base = f.opt()?.map(|v| dec::uint(v, "beacons base")).transpose()?;
    let width = u8::try_from(f.uint()?).ok().filter(|w| (MIN_FILTER_WIDTH..=MAX_FILTER_WIDTH).contains(w)).ok_or(Error::Malformed("filter width"))?;
    let (lo, hi) = (f.uint()?, f.uint()?);
    if lo >= hi || hi > 1 << width {
        return Err(Error::Malformed("filter page range"));
    }
    let gcs = f.bytes(MAX_MESSAGE)?;
    if crate::filter::count_gcs(&gcs, lo, hi)? > MAX_FILTER_ENTRIES {
        return Err(Error::Cap("filter entries"));
    }
    Ok(Msg::Beacons { id, generation, base, f: width, lo, hi, gcs, more: f.bool()? })
}

/// `[actor_proof*]`, at most `MAX_PROOFS`: past it the message is refused whole.
fn proofs(f: &mut Fields) -> Result<Vec<ActorProof>, Error> {
    f.list(0, MAX_PROOFS, "proofs")?.into_iter().map(ActorProof::from_value).collect()
}

fn proofs_value(proofs: &[ActorProof]) -> Value {
    Value::List(proofs.iter().map(ActorProof::to_value).collect())
}

/// `[rotation*]`, at most `MAX_PROVE_ROTATIONS`: each a header-only copy
/// `[Header, signature, Opt(inner), [signature*], []]` (spec/wire.md §4), judged by the engine.
fn rotations(v: Value) -> Result<Vec<Value>, Error> {
    dec::list(v, 0, MAX_PROVE_ROTATIONS, "rotations")?
        .into_iter()
        .map(|r| match &r {
            Value::List(items) if items.len() == 5 && items.last().is_some_and(|s| matches!(s, Value::List(l) if l.is_empty())) => Ok(r),
            _ => Err(Error::Malformed("rotation")),
        })
        .collect()
}

/// `suspect := [thing, ak, digest]`.
fn suspect_entry(v: Value) -> Result<SuspectEntry, Error> {
    let mut g = Fields::exact(v, 3, "suspect")?;
    let thing = Tid::from_bytes(g.fixed()?);
    let Value::Str(ak) = g.next()? else { return Err(Error::Malformed("suspect ak")) };
    let ak = Ak::new(ak).map_err(|_| Error::Malformed("suspect ak"))?;
    Ok(SuspectEntry { thing, ak, digest: g.fixed()? })
}

/// A reply allowance: `SMALL_REPLY..=REPLY_BUDGET` (spec/wire.md §11.2).
fn max_reply(f: &mut Fields) -> Result<u64, Error> {
    let m = f.uint()?;
    if m < SMALL_REPLY as u64 || m > REPLY_BUDGET as u64 {
        return Err(Error::Malformed("max_reply"));
    }
    Ok(m)
}

/// A subscription's id: a request id, so nonzero and below 2^32.
fn sub_id(f: &mut Fields) -> Result<Id, Error> {
    match f.uint()? {
        0 => Err(Error::Malformed("sub id 0")),
        n => Id::try_from(n).map_err(|_| Error::Malformed("sub id")),
    }
}

fn sync_id(f: &mut Fields) -> Result<SyncId, Error> {
    Ok(SyncId(f.fixed()?))
}

fn step(v: Value, n: &Items) -> Result<Step, Error> {
    let bytes = dec::bytes(v, MAX_STEP_BYTES, "step")?;
    Ok(Step::from_value(&n.decode(&bytes, MAX_OBJECT_DEPTH)?)?)
}

fn step_value(s: &Step) -> Value {
    Value::Bytes(s.to_bytes())
}

fn claim_set(v: Value, n: &Items) -> Result<ClaimSet, Error> {
    let bytes = dec::bytes(v, osis_label::step::MAX_CLAIM_SET, "claim set")?;
    Ok(ClaimSet::from_value(&n.decode(&bytes, MAX_OBJECT_DEPTH)?)?)
}

fn offer_item(v: Value) -> Result<OfferItem, Error> {
    let mut f = Fields::range(v, 2, 5, "offer item")?;
    let item = match (f.uint()?, f.remaining()) {
        (0, 2) => OfferItem::Hit { hit: f.fixed()?, sig: f.opt()?.map(|v| dec::fixed(v, "open signature").map(Signature)).transpose()? },
        (1, 2) => OfferItem::ByRole { sync_id: sync_id(&mut f)?, hits: f.list(0, MAX_ITEM_HITS, "hits")?.into_iter().map(|v| dec::fixed(v, "hit")).collect::<Result<_, _>>()? },
        (2, 4) => OfferItem::Deposit(DepositItem { sync_id: sync_id(&mut f)?, blob: f.bytes(MAX_BLOB)?, wrap: f.fixed()?, sig: Signature(f.fixed()?) }),
        (3, 4) => OfferItem::Behind(BehindItem { sync_id: sync_id(&mut f)?, step: f.opt()?.map(|v| dec::fixed(v, "behind step").map(StepId)).transpose()?, key: f.fixed()?, sig: Signature(f.fixed()?) }),
        (4, 3) => OfferItem::Static { hit: f.fixed()?, signing_pk: f.fixed()?, sig: Signature(f.fixed()?) },
        _ => return Err(Error::Malformed("offer item")),
    };
    f.end()?;
    Ok(item)
}

fn offer_item_value(i: &OfferItem) -> Value {
    let sig = |s: &Signature| Value::bytes(&s.0);
    Value::List(match i {
        OfferItem::Hit { hit, sig: s } => vec![Value::uint(0), Value::bytes(hit), Value::opt(s.as_ref().map(sig))],
        OfferItem::ByRole { sync_id, hits } => vec![Value::uint(1), Value::bytes(&sync_id.0), Value::List(hits.iter().map(|h| Value::bytes(h)).collect())],
        OfferItem::Deposit(d) => vec![Value::uint(2), Value::bytes(&d.sync_id.0), Value::bytes(&d.blob), Value::bytes(&d.wrap), sig(&d.sig)],
        OfferItem::Behind(b) => vec![Value::uint(3), Value::bytes(&b.sync_id.0), Value::opt(b.step.as_ref().map(|s| Value::bytes(&s.0))), Value::bytes(&b.key), sig(&b.sig)],
        OfferItem::Static { hit, signing_pk, sig: s } => vec![Value::uint(4), Value::bytes(hit), Value::bytes(signing_pk), sig(s)],
    })
}

fn shared_item(v: Value, n: &Items) -> Result<SharedItem, Error> {
    let mut g = Fields::exact(v, 4, "shared item")?;
    let item = SharedItem {
        code: Code(g.uint()?),
        tag: g.opt()?.map(|v| dec::fixed(v, "tag")).transpose()?,
        grant: g.opt()?.map(|v| grant(v, n)).transpose()?,
        sig: g.opt()?.map(|v| dec::fixed(v, "open signature").map(Signature)).transpose()?,
    };
    let carries = item.tag.is_some() || item.grant.is_some() || item.sig.is_some();
    if (item.code != Code::OK && carries) || (item.sig.is_some() && item.tag.is_none()) {
        return Err(Error::Malformed("shared item"));
    }
    Ok(item)
}

fn shared_item_value(i: &SharedItem) -> Value {
    Value::List(vec![
        Value::uint(i.code.0),
        Value::opt(i.tag.as_ref().map(|t| Value::bytes(t))),
        Value::opt(i.grant.as_ref().map(|g| Value::List(vec![Value::opt(g.entry_box.as_ref().map(|e| Value::Bytes(cbor::encode(&e.to_value())))), Value::List(g.steps.iter().map(step_value).collect())]))),
        Value::opt(i.sig.as_ref().map(|s| Value::bytes(&s.0))),
    ])
}

fn grant(v: Value, n: &Items) -> Result<Grant, Error> {
    let mut f = Fields::exact(v, 2, "grant")?;
    let entry_box = f.opt()?.map(|v| entry_box(v, n)).transpose()?;
    let steps = f.list(1, usize::MAX, "grant steps")?.into_iter().map(|v| step(v, n)).collect::<Result<_, _>>()?;
    Ok(Grant { entry_box, steps })
}

/// An entry box: the canonical bytes of a `box` value in the sealed form (spec/wire.md §7).
fn entry_box(v: Value, n: &Items) -> Result<SecretBox, Error> {
    let bytes = dec::bytes(v, MAX_MESSAGE, "entry box")?;
    Ok(osis_label::step::entry_box_from_value(&n.decode(&bytes, MAX_VALUE_DEPTH)?)?)
}

fn fetched(v: Value) -> Result<Fetched, Error> {
    let mut f = Fields::exact(v, 2, "fetch item")?;
    let blob_id = BlobId(f.fixed()?);
    let entry = match f.opt()? {
        None => None,
        Some(v) => {
            let mut e = Fields::exact(v, 3, "fetch entry")?;
            let r = (e.bytes(MAX_BLOB)?, e.fixed()?, e.opt()?.map(|v| dec::fixed(v, "stamp").map(Signature)).transpose()?);
            e.end()?;
            Some(r)
        }
    };
    f.end()?;
    Ok(Fetched { blob_id, entry })
}

fn fetched_value(f: &Fetched) -> Value {
    let e = f.entry.as_ref().map(|(blob, wrap, stamp)| Value::List(vec![Value::bytes(blob), Value::bytes(wrap), Value::opt(stamp.as_ref().map(|s| Value::bytes(&s.0)))]));
    Value::List(vec![Value::bytes(&f.blob_id.0), Value::opt(e)])
}

fn event(v: Value, n: &Items) -> Result<Event, Error> {
    let mut f = Fields::range(v, 2, 5, "event")?;
    let e = match (f.uint()?, f.remaining()) {
        (0, 4) => Event::Added {
            blob_id: BlobId(f.fixed()?),
            blob: f.opt()?.map(|v| dec::bytes(v, MAX_BLOB, "blob")).transpose()?,
            wrap: f.fixed()?,
            stamp: f.opt()?.map(|v| dec::fixed(v, "stamp").map(Signature)).transpose()?,
        },
        (1, 1) => Event::Deleted(BlobId(f.fixed()?)),
        (2, 1) => Event::Full(f.bool()?),
        (3, 1) => Event::Head(step(f.next()?, n)?),
        (4, 2) => match (BlobId(f.fixed()?), Code(f.uint()?)) {
            (_, Code::OK | Code::STORAGE_CAP) => return Err(Error::Malformed("refused event code")),
            (b, c) => Event::Refused(b, c),
        },
        _ => return Err(Error::Malformed("event")),
    };
    f.end()?;
    Ok(e)
}

fn event_value(e: &Event) -> Value {
    Value::List(match e {
        Event::Added { blob_id, blob, wrap, stamp } => vec![Value::uint(0), Value::bytes(&blob_id.0), Value::opt(blob.as_deref().map(Value::bytes)), Value::bytes(wrap), Value::opt(stamp.as_ref().map(|s| Value::bytes(&s.0)))],
        Event::Deleted(id) => vec![Value::uint(1), Value::bytes(&id.0)],
        Event::Full(full) => vec![Value::uint(2), Value::Bool(*full)],
        Event::Head(step) => vec![Value::uint(3), step_value(step)],
        Event::Refused(id, code) => vec![Value::uint(4), Value::bytes(&id.0), Value::uint(code.0)],
    })
}

/// Bytes `[sync_id, event]` takes inside a PullReply or Stream, exactly: what a server pages by
/// against `max_reply`. Counted from the heads, so nothing is copied.
pub fn stream_event_len(e: &Event) -> usize {
    let bstr = |n: usize| cbor::head_len(n as u64) + n;
    let uint = |n: u64| cbor::head_len(n);
    let opt = |inner: Option<usize>| 1 + inner.unwrap_or(0);
    let event = match e {
        Event::Added { blob, stamp, .. } => 1 + 1 + bstr(32) + opt(blob.as_ref().map(|b| bstr(b.len()))) + bstr(WRAP_LEN) + opt(stamp.map(|_| bstr(64))),
        Event::Deleted(_) => 1 + 1 + bstr(32),
        Event::Full(_) => 1 + 1 + 1,
        Event::Head(s) => 1 + 1 + bstr(s.to_bytes().len()),
        Event::Refused(_, c) => 1 + 1 + bstr(32) + uint(c.0),
    };
    1 + bstr(16) + event
}

fn events(vs: Vec<Value>, n: &Items) -> Result<Vec<(SyncId, Event)>, Error> {
    vs.into_iter()
        .map(|v| {
            let mut g = Fields::exact(v, 2, "stream event")?;
            let s = sync_id(&mut g)?;
            let e = event(g.next()?, n)?;
            Ok((s, e))
        })
        .collect()
}

fn events_value(es: &[(SyncId, Event)]) -> Value {
    Value::List(es.iter().map(|(s, e)| Value::List(vec![Value::bytes(&s.0), event_value(e)])).collect())
}

fn opt_cursor(c: &Option<Cursor>) -> Value {
    Value::opt(c.as_ref().map(|c| Value::bytes(c.as_bytes())))
}

fn opt_cursor_of(f: &mut Fields) -> Result<Option<Cursor>, Error> {
    f.opt()?.map(|v| dec::bytes(v, MAX_CURSOR_BYTES, "cursor").and_then(Cursor::new)).transpose()
}

fn joins(vs: Vec<Value>) -> Result<Vec<Join>, Error> {
    vs.into_iter()
        .map(|v| {
            let mut g = Fields::exact(v, 2, "join")?;
            Ok((sync_id(&mut g)?, opt_cursor_of(&mut g)?))
        })
        .collect()
}

fn joins_value(js: &[Join]) -> Value {
    Value::List(js.iter().map(|(s, c)| Value::List(vec![Value::bytes(&s.0), opt_cursor(c)])).collect())
}

#[cfg(test)]
mod tests;
