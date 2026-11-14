//! Protocol version 1 messages (spec/wire.md §11.2) with their caps and limits (§13). Label
//! objects are osis-label's types (steps, claim sets, proofs, delete items)
//! and the entry box is a `box` value; the wire carries steps, claim sets and boxes as their
//! canonical bytes.

use crate::Error;
use crate::dec::{self, Fields};
use osis_base::format::{MAX_BLOB, MAX_MESSAGE};
use osis_base::{BlobId, LabelId, Limits, Value, cbor};
pub use osis_crypto::Signature;
pub use osis_label::{ClaimSet, DeleteItem, Step, StepId};
use osis_schema::Codec;
pub use osis_schema::core_types::SecretBox;

pub const WRAP_LEN: usize = osis_crypto::WRAP_LEN;
pub type Wrap = [u8; WRAP_LEN];

/// Per-message caps (spec/wire.md §11.2).
pub const MAX_ITEMS: usize = 1024;
/// A canonical `Step` is at most this long (spec/wire.md §8: nine fixed-size items).
pub const MAX_STEP_BYTES: usize = 323;
/// A step's greatest encoding in a message: its bytes as a CBOR byte string (3 header bytes).
pub const MAX_STEP_WIRE: usize = MAX_STEP_BYTES + 3;
/// Request ids are below 2^32 (spec/wire.md §11.1).
pub type Id = u32;
/// The ids a node draws for the shared set's and the stream's requests (spec/wire.md §11.2):
/// the top bit set, so they never equal a session's own.
pub const NODE_IDS: Id = 1 << 31;

/// Deepest nesting of any v1 message: a sync message is at most 6 deep (FetchReply); a Call's
/// args or a Reply's value hold values (64 deep, spec/data-model.md §5) inside at most 16 levels
/// of call structure (a write batch: message, args, batch, op, path, step).
const MESSAGE_DEPTH: usize = osis_base::format::MAX_VALUE_DEPTH + 16;
/// CBOR data items in one message, counted before any is decoded (spec/wire.md §13). Resource
/// bound: a decoded item costs about 100 bytes (`Value`), so a frame of one-byte items would
/// otherwise cost about 2 GB; the densest message an engine sends (a reply of deletion or pending
/// events, paged by `event_size`) holds under 800 000, the densest any valid peer can send (one-
/// byte `at`s) about 1 021 000, so the cap refuses no message valid by the other rules. 0: no
/// message decodes; infinity: up to about 250 bytes of memory per frame byte from any peer that
/// sent a Hello (one-item lists).
pub const MAX_MESSAGE_ITEMS: usize = 1 << 20;

/// Status codes (spec/wire.md §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(pub u64);

impl Code {
    pub const OK: Code = Code(0);
    pub const REFUSED: Code = Code(1);
    pub const MALFORMED: Code = Code(2);
    pub const TOO_LARGE: Code = Code(3);
    pub const RATE_LIMITED: Code = Code(4);
    pub const BUDGET_FULL: Code = Code(5);
    pub const TOMBSTONED: Code = Code(6);
    pub const EXPIRED: Code = Code(7);
    pub const NOT_OPENED: Code = Code(8);
    pub const NOT_HEAD: Code = Code(9);
    pub const UNSUPPORTED: Code = Code(11);
    pub const STORAGE_CAP: Code = Code(12);
    pub const UNKNOWN_LABEL: Code = Code(13);
    pub const NOT_ADMITTED: Code = Code(14);
}


/// `event := [0, blob_id, Opt(blob), wrap, Opt(stamp)] | [1, blob_id] | [2, full] | [3, step] | [4, blob_id, code]`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // steps carry parsed keys; boxing buys nothing here
pub enum Event {
    /// Entry added or its wrap and stamp replaced; no stamp: deposited.
    Added { blob_id: BlobId, blob: Option<Vec<u8>>, wrap: Wrap, stamp: Option<Signature> },
    Deleted(BlobId),
    /// New head, without claim set.
    Head(Step),
    /// The sending node, which cannot read the label, refused an entry of it it pulled for room
    /// (true), or has room again (false): carried by a Stream without cursor (spec/sync-opens.md §4).
    Full(bool),
    /// The sending node, which cannot read the label, refused an entry of it it pulled, for
    /// anything but room (`Full`): carried by a Stream without cursor (spec/sync-opens.md §4).
    Refused(BlobId, Code),
}

/// A Fetch reply item: the entry of the label, or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    pub blob_id: BlobId,
    pub entry: Option<(Vec<u8>, Wrap, Option<Signature>)>,
}

/// Every v1 message after Hello.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // a Register's step carries parsed keys; one per message
pub enum Message {
    Error { id: Id, code: Code },
    Ok { id: Id },
    Ping { id: Id, wall_ms: u64 },
    Pong { id: Id, wall_ms: u64 },
    Register { id: Id, label: LabelId, step: Step, claim_set: Option<ClaimSet> },
    /// One code per item of a Delete, in order.
    Status { id: Id, codes: Vec<Code> },
    Delete { id: Id, label: LabelId, items: Vec<DeleteItem> },
    Fetch { id: Id, label: LabelId, max_reply: u64, ids: Vec<BlobId> },
    FetchReply { id: Id, items: Vec<Fetched> },
    /// Client port (notes/client-port.md §2): a main session sends no secret, a thin client
    /// its bearer secret (`Debug` redacted, zeroized on drop).
    Auth { id: Id, secret: Option<osis_crypto::Secret32>, session: [u8; 16] },
    /// The dialer's connection proofs (spec/sync-opens.md §4); at most one per connection.
    Prove { id: Id, proofs: Vec<crate::ActorProof> },
    /// The listener's answer: its own proofs, none unless the dialer proved a known actor.
    Proved { id: Id, proofs: Vec<crate::ActorProof> },
    /// The sender is stranded on this label (spec/permissions.md §4), naming the holder it reads
    /// the label's actor through, with that holder's current keys: node to node, answered Ok.
    Stranded { id: Id, label: LabelId, holder: osis_base::Tid, keys: osis_label::HolderKeys },
    /// Aspects of things in the label's closure the sender flags suspect (spec/permissions.md
    /// §4): node to node, answered Ok.
    Suspect { id: Id, label: LabelId, entries: Vec<SuspectEntry> },
    /// The dialer's records for this peer (spec/sync-opens.md §3, pair key); at most one per
    /// connection, after Proved.
    Resume { id: Id, nonce: [u8; 32], tags: Vec<[u8; 32]> },
    /// The listener's nonce, and the answering tag of a record it holds, if any.
    Resumed { id: Id, nonce: [u8; 32], tag: Option<[u8; 32]> },
    /// The dialer keeps no record of this listener: the connection's shared set runs under the
    /// connection's own pair key (spec/sync-opens.md §3, pair key).
    NoRecord { id: Id },
    /// One generation of a side's beacon filter, in pages (issues/sync-rewrite.md).
    Beacons { id: Id, generation: u64, base: Option<u64>, f: u8, lo: u64, hi: u64, gcs: Vec<u8>, more: bool },
    /// What this side offers from testing the peer's filter (Hits, then ByRole).
    Offer { id: Id, items: Vec<OfferItem> },
    /// This side no longer shares these sync IDs (each with where it stopped, when known).
    Lost { id: Id, items: Vec<(LabelId, Option<Vec<u8>>)> },
    /// The answer to a Beacons, Offer or Lost: one entry per item, in order (one for a Beacons).
    Shared { id: Id, codes: Vec<SharedCode> },
    /// A pull of the peer's node log stream (spec/sync-streams.md §4, stream): the events after
    /// `cursor` of the shared set's members, and each join's after its own cursor (from the
    /// start when it has none).
    Pull(Box<Pull>),
    /// The answer to a Pull.
    PullReply(Box<PullReply>),
    /// The followed stream's next events, pushed (id 0).
    Stream(Box<Stream>),
    /// The requester applied what `cursor` covers (id 0).
    Applied { cursor: Vec<u8> },
    /// The digest of the record's shared set, a connection's first message each way after Resume
    /// (id 0; spec/sync-opens.md §3, agreement).
    Digest { digest: [u8; 32] },
    /// A page of the sender's shared set, sent only when the digests differ (id 0).
    Members { labels: Vec<LabelId>, more: bool },
    /// `max_reply`: the reply's frame body bound, `SMALL_REPLY..=REPLY_BUDGET`; `args` a list.
    Call { id: Id, max_reply: u64, method: u64, args: Vec<Value> },
    Reply { id: Id, outcome: crate::api::Outcome },
    /// The request id names the subscription until its Unsub is answered or it lapsed.
    Sub { id: Id, max_reply: u64, filter: Value },
    Unsub { id: Id, sub: Id },
    Notify { sub: Id, payload: crate::api::Payload },
}

/// A suspect entry (spec/wire.md §11.2 Suspect): the aspect and its keyed state digest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuspectEntry {
    pub thing: osis_base::Tid,
    pub ak: osis_base::Ak,
    pub digest: [u8; 16],
}

impl SuspectEntry {
    /// Its encoded size within a Suspect message, an upper bound.
    pub fn size(&self) -> usize {
        self.ak.as_str().len() + 48
    }
}

/// A member entering a Pull's stream, from its own cursor or (none) the start.
pub type Join = (LabelId, Option<Vec<u8>>);

/// `Pull [41, id, Opt(cursor), [join*], inline_limit, max_reply, follow, ephemeral]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pull {
    pub id: Id,
    pub cursor: Option<Vec<u8>>,
    pub joins: Vec<Join>,
    pub inline_limit: u64,
    pub max_reply: u64,
    pub follow: bool,
    pub ephemeral: bool,
}

/// `PullReply [42, id, [[label_id, event]*], Opt(cursor), whole, trimmed, more, report, [join*]]`:
/// `trimmed` (with `whole`): a cursor the Pull named is on this store's history below its
/// deletion horizon, so deletions since it are not all in the log. `joins` are the Pull's joins
/// not in the stream at `cursor`: still in pages at their own cursor, or (none) not shared here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullReply {
    pub id: Id,
    pub events: Vec<(LabelId, Event)>,
    pub cursor: Option<Vec<u8>>,
    pub whole: bool,
    pub trimmed: bool,
    pub more: bool,
    pub report: bool,
    pub joins: Vec<Join>,
}

/// `Stream [43, 0, [[label_id, event]*], Opt(cursor), report, seq]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub events: Vec<(LabelId, Event)>,
    pub cursor: Option<Vec<u8>>,
    pub report: bool,
    /// Pushes with a cursor the sender sent on the connection since its last PullReply (0 in
    /// one without a cursor): a requester takes a push only in that order (spec/wire.md §11.2).
    pub seq: u64,
}

/// One Offer item (spec/wire.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferItem {
    /// A Hit: the role-bound digest of a credential whose filter entry hit (`beacon_hit`), with
    /// the credential's proof where its match value is public: for a sync key, an open signature
    /// by it (spec/sync-opens.md §4).
    Hit([u8; 32], Option<Signature>),
    /// A sync ID the sender judged the peer holds, with the sender's Hit at each epoch it holds.
    ByRole(LabelId, Vec<[u8; 32]>),
    /// An inbox blob for inbox sync ID `label`, its wrap and the deposit key's signature, as a
    /// Deposit carries them, to a peer the sender judged a holder of the inbox.
    Deposit { label: LabelId, blob: Vec<u8>, wrap: Wrap, sig: Signature },
    /// A Hit on a static entry with its key actor's signing key and an open signature by it
    /// (spec/sync-opens.md §4, shared set): opens where the key's static entry is the credential hit.
    Static { hit: [u8; 32], key: [u8; 32], sig: Signature },
    /// The sender is behind the peer's head of `label`: it holds credential key `key` of step
    /// `step` (a sync key, a claim, or a key actor's signing key; none: by a sync key, the newest
    /// step bearing it, by a signing key, the head), proven by an open signature by that key
    /// (spec/sync-ids.md §6, behind). Answered with the steps after it to the head, or a Static
    /// item's grant.
    Behind { label: LabelId, step: Option<StepId>, key: [u8; 32], sig: Signature },
}

/// Most items in one Offer or Lost.
pub const MAX_SHARED_ITEMS: usize = 1024;
/// Most sync IDs in one Members page.
pub const MAX_MEMBERS: usize = 4096;

/// One item's answer in a Shared: its code, the tag of an accepted Hit, and the steps it carries
/// (spec/sync-opens.md §4, shared set).
pub type SharedCode = (Code, Option<[u8; 32]>, Option<Box<Grant>>);

/// Steps an answer carries: for an accepted Hit on the tester's static entry, the box the head's
/// claim set keeps for that entry and the label's path from its genesis step to that head; for
/// an accepted Behind item, the steps after the named one to the head (both without claim sets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub entry_box: Option<SecretBox>,
    pub steps: Vec<Step>,
}
/// Most epochs a ByRole lists.
pub const MAX_BYROLE_HITS: usize = 256;

/// A frame body that is not a valid message: its kind and request id when readable (else 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub kind: u64,
    pub id: Id,
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

    /// Whether the sender expects an answer: a request, or a kind this build does not know.
    pub fn wants_answer(&self) -> bool {
        is_request_kind(self.kind) || matches!(self.error, Error::UnknownKind(_))
    }
}

/// The kind and id of a message from the first bytes of its frame body, when they are there (a
/// frame still arriving); `Message::decode` checks the whole once it is in.
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
    if !(0x80..=0x97).contains(&ib) {
        return None;
    }
    let (kind, rest) = uint(rest)?;
    let (id, _) = uint(rest)?;
    Some((kind, Id::try_from(id).ok()?))
}

/// Kinds that answer a request, by its id (spec/wire.md §11.2: Error, Ok, Pong, Status,
/// FetchReply, Reply, Proved, Resumed, Shared, PullReply).
pub fn is_reply_kind(kind: u64) -> bool {
    matches!(kind, 0 | 1 | 3 | 11 | 20 | 26 | 33 | 35 | 39 | 42)
}

/// Kinds that are requests (spec/wire.md §11.2: those with `->`).
pub fn is_request_kind(kind: u64) -> bool {
    matches!(kind, 2 | 7 | 14 | 19 | 24 | 25 | 27 | 28 | 30 | 31 | 32 | 34 | 36 | 37 | 38 | 40 | 41)
}

impl OfferItem {
    fn to_value(&self) -> Value {
        match self {
            OfferItem::Hit(h, proof) => Value::List(vec![Value::uint(0), Value::bytes(h), Value::opt(proof.as_ref().map(|s| Value::bytes(&s.0)))]),
            OfferItem::ByRole(l, hits) => Value::List(vec![Value::uint(1), Value::bytes(&l.0), Value::List(hits.iter().map(|h| Value::bytes(h)).collect())]),
            OfferItem::Deposit { label, blob, wrap, sig } => Value::List(vec![Value::uint(2), Value::bytes(&label.0), Value::bytes(blob), Value::bytes(wrap), Value::bytes(&sig.0)]),
            OfferItem::Static { hit, key, sig } => Value::List(vec![Value::uint(4), Value::bytes(hit), Value::bytes(key), Value::bytes(&sig.0)]),
            OfferItem::Behind { label, step, key, sig } => Value::List(vec![Value::uint(3), Value::bytes(&label.0), Value::opt(step.as_ref().map(|s| Value::bytes(&s.0))), Value::bytes(key), Value::bytes(&sig.0)]),
        }
    }
}

fn offer_item(v: Value) -> Result<OfferItem, Error> {
    let mut f = Fields::range(v, 2, 5, "offer item")?;
    let item = match f.uint()? {
        0 => OfferItem::Hit(f.fixed()?, f.opt()?.map(|v| dec::fixed(v, "open signature").map(Signature)).transpose()?),
        1 => OfferItem::ByRole(LabelId(f.fixed()?), f.list(1, MAX_BYROLE_HITS, "hits")?.into_iter().map(|v| dec::fixed(v, "hit")).collect::<Result<_, _>>()?),
        2 => OfferItem::Deposit { label: LabelId(f.fixed()?), blob: f.bytes(MAX_BLOB)?, wrap: f.fixed()?, sig: Signature(f.fixed()?) },
        4 => OfferItem::Static { hit: f.fixed()?, key: f.fixed()?, sig: Signature(f.fixed()?) },
        3 => OfferItem::Behind { label: LabelId(f.fixed()?), step: f.opt()?.map(|v| dec::fixed(v, "behind step").map(StepId)).transpose()?, key: f.fixed()?, sig: Signature(f.fixed()?) },
        _ => return Err(Error::Malformed("offer item")),
    };
    if f.remaining() != 0 {
        return Err(Error::Malformed("offer item"));
    }
    Ok(item)
}

fn proofs(v: Vec<Value>) -> Result<Vec<crate::ActorProof>, Error> {
    v.into_iter().map(crate::ActorProof::from_value).collect()
}

fn step_value(s: &Step) -> Value {
    Value::bytes(&s.to_bytes())
}

fn box_bytes(e: &SecretBox) -> Vec<u8> {
    cbor::encode(&e.to_value())
}

impl Message {
    pub fn kind(&self) -> u64 {
        use Message::*;
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

    /// The request id (0 for a push).
    pub fn id(&self) -> Id {
        use Message::*;
        match self {
            Error { id, .. } | Ok { id } | Ping { id, .. } | Pong { id, .. } | Register { id, .. } | Status { id, .. } | Delete { id, .. } | Fetch { id, .. } | FetchReply { id, .. } | Auth { id, .. } | Call { id, .. } | Reply { id, .. } | Sub { id, .. } | Unsub { id, .. } | Stranded { id, .. } | Suspect { id, .. } | Prove { id, .. } | Proved { id, .. } | Resume { id, .. } | Resumed { id, .. } | Beacons { id, .. } | Offer { id, .. } | Lost { id, .. } | Shared { id, .. } | NoRecord { id } => *id,
            Pull(p) => p.id,
            PullReply(r) => r.id,
            Notify { .. } | Stream(_) | Applied { .. } | Digest { .. } | Members { .. } => 0,
        }
    }

    /// Whether the node answers this itself rather than a session: Stranded and Suspect, Prove
    /// and Resume, the shared set's and the stream's messages (spec/wire.md §11.2 Beacons to
    /// NoRecord, Pull to Applied), and any message with an id in the node's range (`NODE_IDS`):
    /// a peer node's own request (a Fetch of the stream's bodies) or the answer to one of this
    /// node's. Proved and Resumed go by id: answers to the upper layer's own Prove and Resume,
    /// handed up as every answer is (`Session`).
    pub fn for_node(&self) -> bool {
        matches!(self.kind(), 30..=32 | 34 | 36..=46) || self.id() & NODE_IDS != 0
    }

    /// Whether this kind is a request the other side answers.
    pub fn is_request(&self) -> bool {
        is_request_kind(self.kind())
    }

    pub fn to_value(&self) -> Value {
        use Message as M;
        let k = Value::uint(self.kind());
        let id = Value::uint(self.id() as u64);
        let l = |x: &LabelId| Value::bytes(&x.0);
        let items = match self {
            M::Error { code, .. } => vec![k, id, Value::uint(code.0)],
            M::Ok { .. } => vec![k, id],
            M::Ping { wall_ms, .. } | M::Pong { wall_ms, .. } => vec![k, id, Value::uint(*wall_ms)],
            M::Register { label, step, claim_set, .. } => vec![k, id, l(label), step_value(step), Value::opt(claim_set.as_ref().map(|c| Value::Bytes(c.to_bytes())))],
            M::Status { codes, .. } => vec![k, id, Value::List(codes.iter().map(|c| Value::uint(c.0)).collect())],
            M::Delete { label, items, .. } => vec![k, id, l(label), Value::List(items.iter().map(DeleteItem::to_value).collect())],
            M::Fetch { label, max_reply, ids, .. } => vec![k, id, l(label), Value::uint(*max_reply), ids_value(ids)],
            M::FetchReply { items, .. } => vec![
                k,
                id,
                Value::List(
                    items
                        .iter()
                        .map(|f| {
                            let e = f.entry.as_ref().map(|(blob, wrap, stamp)| Value::List(vec![Value::bytes(blob), Value::bytes(wrap), Value::opt(stamp.as_ref().map(|s| Value::bytes(&s.0)))]));
                            Value::List(vec![Value::bytes(&f.blob_id.0), Value::opt(e)])
                        })
                        .collect(),
                ),
            ],
            M::Stranded { label, holder, keys, .. } => {
                let [commits, records] = keys.to_values();
                vec![k, id, l(label), Value::Tid(*holder), commits, records]
            }
            M::Suspect { label, entries, .. } => vec![k, id, l(label), Value::List(entries.iter().map(|e| Value::List(vec![Value::Tid(e.thing), Value::Str(e.ak.as_str().to_string()), Value::bytes(&e.digest)])).collect())],
            M::Prove { proofs, .. } | M::Proved { proofs, .. } => vec![k, id, Value::List(proofs.iter().map(crate::ActorProof::to_value).collect())],
            M::Resume { nonce, tags, .. } => vec![k, id, Value::bytes(nonce), Value::List(tags.iter().map(|t| Value::bytes(t)).collect())],
            M::Resumed { nonce, tag, .. } => vec![k, id, Value::bytes(nonce), Value::opt(tag.as_ref().map(|t| Value::bytes(t)))],
            M::Beacons { generation, base, f, lo, hi, gcs, more, .. } => vec![k, id, Value::uint(*generation), Value::opt(base.map(Value::uint)), Value::uint(u64::from(*f)), Value::uint(*lo), Value::uint(*hi), Value::bytes(gcs), Value::Bool(*more)],
            M::NoRecord { .. } => vec![k, id],
            M::Offer { items, .. } => vec![k, id, Value::List(items.iter().map(OfferItem::to_value).collect())],
            M::Lost { items, .. } => vec![k, id, Value::List(items.iter().map(|(l, c)| Value::List(vec![Value::bytes(&l.0), Value::opt(c.as_ref().map(|c| Value::bytes(c)))])).collect())],
            M::Shared { codes, .. } => vec![k, id, Value::List(codes.iter().map(|(c, t, g)| Value::List(vec![Value::uint(c.0), Value::opt(t.as_ref().map(|t| Value::bytes(t))), Value::opt(g.as_ref().map(|g| Value::List(vec![Value::opt(g.entry_box.as_ref().map(|e| Value::Bytes(box_bytes(e)))), Value::List(g.steps.iter().map(step_value).collect())])))])).collect())],
            M::Pull(p) => vec![k, id, opt_cursor(&p.cursor), joins_value(&p.joins), Value::uint(p.inline_limit), Value::uint(p.max_reply), Value::Bool(p.follow), Value::Bool(p.ephemeral)],
            M::PullReply(r) => vec![k, id, stream_events_value(&r.events), opt_cursor(&r.cursor), Value::Bool(r.whole), Value::Bool(r.trimmed), Value::Bool(r.more), Value::Bool(r.report), joins_value(&r.joins)],
            M::Stream(s) => vec![k, id, stream_events_value(&s.events), opt_cursor(&s.cursor), Value::Bool(s.report), Value::uint(s.seq)],
            M::Applied { cursor } => vec![k, id, Value::bytes(cursor)],
            M::Digest { digest } => vec![k, id, Value::bytes(digest)],
            M::Members { labels, more } => vec![k, id, Value::List(labels.iter().map(l).collect()), Value::Bool(*more)],
            M::Auth { secret, session, .. } => vec![k, id, Value::opt(secret.as_ref().map(|s| Value::bytes(s.expose()))), Value::bytes(session)],
            M::Call { max_reply, method, args, .. } => vec![k, id, Value::uint(*max_reply), Value::uint(*method), Value::List(args.clone())],
            M::Reply { outcome, .. } => vec![k, id, outcome.to_value()],
            M::Sub { max_reply, filter, .. } => vec![k, id, Value::uint(*max_reply), filter.clone()],
            M::Unsub { sub, .. } => vec![k, id, Value::uint(u64::from(*sub))],
            M::Notify { sub, payload } => vec![k, id, Value::uint(u64::from(*sub)), payload.to_value()],
        };
        Value::List(items)
    }

    /// The frame body. Callers keep it within `MAX_MESSAGE` (the engines page).
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// Decodes a frame body, enforcing every layout rule and cap of spec/wire.md §11.2, §13.
    pub fn decode(body: &[u8]) -> Result<Message, Rejected> {
        let limits = Limits { max_depth: MESSAGE_DEPTH, max_bytes: MAX_MESSAGE };
        let mut items = 0usize;
        cbor::visit_items(body, &limits, &mut |_, _, _| items += 1).map_err(|e| Rejected { kind: 0, id: 0, error: e.into() })?;
        if items > MAX_MESSAGE_ITEMS {
            return Err(Rejected { kind: 0, id: 0, error: Error::Cap("message items") });
        }
        let v = cbor::decode(body, &limits).map_err(|e| Rejected { kind: 0, id: 0, error: e.into() })?;
        let (kind, id) = match &v {
            Value::List(items) => match (items.first(), items.get(1)) {
                (Some(Value::Int(k)), Some(Value::Int(i))) if *k >= 0 && *i >= 0 && *i < (1i64 << 32) => (*k as u64, *i as u32),
                _ => return Err(Rejected { kind: 0, id: 0, error: Error::Malformed("message head") }),
            },
            _ => return Err(Rejected { kind: 0, id: 0, error: Error::Malformed("message head") }),
        };
        decode_body(kind, id, v).map_err(|error| Rejected { kind, id, error })
    }
}

fn decode_body(kind: u64, id: Id, v: Value) -> Result<Message, Error> {
    let mut f = Fields::range(v, 2, usize::MAX, "message")?;
    f.next()?;
    f.next()?;
    let msg = match kind {
        0 => Message::Error { id, code: Code(f.uint()?) },
        1 => Message::Ok { id },
        2 => Message::Ping { id, wall_ms: f.uint()? },
        3 => Message::Pong { id, wall_ms: f.uint()? },
        7 => Message::Register { id, label: label(&mut f)?, step: step(&mut f)?, claim_set: f.opt()?.map(claim_set).transpose()? },
        11 => Message::Status { id, codes: f.list(1, usize::MAX, "status codes")?.into_iter().map(|v| dec::uint(v, "code").map(Code)).collect::<Result<_, _>>()? },
        14 => {
            let label = label(&mut f)?;
            let items = f.list(1, MAX_ITEMS, "delete items")?.iter().map(DeleteItem::from_value).collect::<Result<_, _>>()?;
            Message::Delete { id, label, items }
        }
        19 => Message::Fetch { id, label: label(&mut f)?, max_reply: max_reply(&mut f)?, ids: ids(f.list(1, MAX_ITEMS, "fetch ids")?)? },
        20 => Message::FetchReply { id, items: f.list(0, MAX_ITEMS, "fetch items")?.into_iter().map(fetched).collect::<Result<_, _>>()? },
        24 => Message::Auth {
            id,
            secret: f.opt()?.map(|v| dec::fixed(v, "client secret").map(osis_crypto::Secret32::from_bytes)).transpose()?,
            session: f.fixed()?,
        },
        25 => Message::Call { id, max_reply: max_reply(&mut f)?, method: f.uint()?, args: f.list(0, usize::MAX, "args")? },
        26 => Message::Reply { id, outcome: crate::api::Outcome::from_value(f.next()?)? },
        27 => Message::Sub { id, max_reply: max_reply(&mut f)?, filter: f.next()? },
        28 => Message::Unsub { id, sub: sub_id(&mut f)? },
        29 => Message::Notify { sub: sub_id(&mut f)?, payload: crate::api::Payload::from_value(f.next()?)? },
        30 => {
            let label = label(&mut f)?;
            let Value::Tid(holder) = f.next()? else { return Err(Error::Malformed("stranded holder")) };
            let (commits, records) = (f.next()?, f.next()?);
            Message::Stranded { id, label, holder, keys: osis_label::HolderKeys::from_values(&commits, &records).map_err(|_| Error::Malformed("stranded keys"))? }
        }
        31 => Message::Suspect { id, label: label(&mut f)?, entries: f.list(1, usize::MAX, "suspect entries")?.into_iter().map(suspect_entry).collect::<Result<_, _>>()? },
        32 => Message::Prove { id, proofs: proofs(f.list(0, crate::prove::MAX_PROOFS, "proofs")?)? },
        33 => Message::Proved { id, proofs: proofs(f.list(0, crate::prove::MAX_PROOFS, "proofs")?)? },
        34 => Message::Resume { id, nonce: f.fixed()?, tags: f.list(0, crate::prove::MAX_RESUME_TAGS, "tags")?.into_iter().map(|v| dec::fixed(v, "tag")).collect::<Result<_, _>>()? },
        35 => Message::Resumed { id, nonce: f.fixed()?, tag: f.opt()?.map(|v| dec::fixed(v, "tag")).transpose()? },
        40 => Message::NoRecord { id },
        41 => Message::Pull(Box::new(Pull {
            id,
            cursor: opt_cursor_of(&mut f)?,
            joins: joins(f.list(0, usize::MAX, "joins")?)?,
            inline_limit: f.uint()?,
            max_reply: max_reply(&mut f)?,
            follow: f.bool()?,
            ephemeral: f.bool()?,
        })),
        42 => Message::PullReply(Box::new(PullReply {
            id,
            events: stream_events(f.list(0, usize::MAX, "events")?)?,
            cursor: opt_cursor_of(&mut f)?,
            whole: f.bool()?,
            trimmed: f.bool()?,
            more: f.bool()?,
            report: f.bool()?,
            joins: joins(f.list(0, usize::MAX, "joins")?)?,
        })),
        43 => Message::Stream(Box::new(Stream { events: stream_events(f.list(0, usize::MAX, "events")?)?, cursor: opt_cursor_of(&mut f)?, report: f.bool()?, seq: f.uint()? })),
        44 => Message::Applied { cursor: f.bytes(crate::MAX_CURSOR_BYTES)? },
        45 => Message::Digest { digest: f.fixed()? },
        46 => Message::Members { labels: labels(f.list(0, MAX_MEMBERS, "members")?)?, more: f.bool()? },
        36 => Message::Beacons {
            id,
            generation: f.uint()?,
            base: f.opt()?.map(|v| dec::uint(v, "base")).transpose()?,
            f: u8::try_from(f.uint()?).map_err(|_| Error::Malformed("beacon width"))?,
            lo: f.uint()?,
            hi: f.uint()?,
            gcs: f.bytes(usize::MAX)?,
            more: f.bool()?,
        },
        37 => Message::Offer { id, items: f.list(1, MAX_SHARED_ITEMS, "offer")?.into_iter().map(offer_item).collect::<Result<_, _>>()? },
        38 => Message::Lost {
            id,
            items: f
                .list(1, MAX_SHARED_ITEMS, "lost")?
                .into_iter()
                .map(|v| {
                    let mut g = Fields::exact(v, 2, "lost item")?;
                    let l = LabelId(g.fixed()?);
                    let c = g.opt()?.map(|v| dec::bytes(v, crate::MAX_CURSOR_BYTES, "cursor")).transpose()?;
                    Ok((l, c))
                })
                .collect::<Result<_, Error>>()?,
        },
        39 => Message::Shared {
            id,
            codes: f
                .list(1, MAX_SHARED_ITEMS, "codes")?
                .into_iter()
                .map(|v| {
                    let mut g = Fields::exact(v, 3, "code")?;
                    let c = Code(g.uint()?);
                    let t = g.opt()?.map(|v| dec::fixed(v, "tag")).transpose()?;
                    let e = g.opt()?.map(grant).transpose()?.map(Box::new);
                    Ok((c, t, e))
                })
                .collect::<Result<_, Error>>()?,
        },
        _ => return Err(Error::UnknownKind(kind)),
    };
    f.end()?;
    // Pushes have no reply (id 0); every request and reply has a real id; an Error answering a
    // broken frame may carry 0.
    match (kind, id) {
        (29 | 43..=46, 0) | (0, _) => Ok(msg),
        (29 | 43..=46, _) => Err(Error::Malformed("id of a message without reply")),
        (_, 0) => Err(Error::Malformed("id 0")),
        _ => Ok(msg),
    }
}

/// `suspect := [thing, ak, digest]`.
fn suspect_entry(v: Value) -> Result<SuspectEntry, Error> {
    let mut g = Fields::exact(v, 3, "suspect")?;
    let Value::Tid(thing) = g.next()? else { return Err(Error::Malformed("suspect thing")) };
    let Value::Str(ak) = g.next()? else { return Err(Error::Malformed("suspect ak")) };
    let ak = osis_base::Ak::new(&ak).map_err(|_| Error::Malformed("suspect ak"))?;
    Ok(SuspectEntry { thing, ak, digest: g.fixed()? })
}

/// A reply allowance: `SMALL_REPLY..=REPLY_BUDGET` (spec/wire.md §11.2).
fn max_reply(f: &mut Fields) -> Result<u64, Error> {
    let m = f.uint()?;
    if m < crate::window::SMALL_REPLY as u64 || m > crate::session::REPLY_BUDGET as u64 {
        return Err(Error::Malformed("max_reply"));
    }
    Ok(m)
}

/// A subscription's id: a nonzero request id.
fn sub_id(f: &mut Fields) -> Result<Id, Error> {
    match f.uint()? {
        0 => Err(Error::Malformed("sub id 0")),
        n => Id::try_from(n).map_err(|_| Error::Malformed("sub id")),
    }
}

fn label(f: &mut Fields) -> Result<LabelId, Error> {
    Ok(LabelId(f.fixed()?))
}

fn step_of(v: Value) -> Result<Step, Error> {
    Ok(Step::parse(&dec::bytes(v, MAX_STEP_BYTES, "step")?)?)
}

fn step(f: &mut Fields) -> Result<Step, Error> {
    step_of(f.next()?)
}

fn claim_set(v: Value) -> Result<ClaimSet, Error> {
    Ok(ClaimSet::parse(&dec::bytes(v, osis_label::step::MAX_CLAIM_SET, "claim set")?)?)
}

fn grant(v: Value) -> Result<Grant, Error> {
    let mut f = Fields::exact(v, 2, "grant")?;
    let entry_box = f.opt()?.map(entry_box).transpose()?;
    let steps = f.list(1, usize::MAX, "grant steps")?.into_iter().map(step_of).collect::<Result<_, _>>()?;
    Ok(Grant { entry_box, steps })
}

/// A `box` value as canonical bytes; it must re-encode to itself.
fn entry_box(v: Value) -> Result<SecretBox, Error> {
    let bytes = dec::bytes(v, MAX_MESSAGE, "entry box")?;
    let v = cbor::decode(&bytes, &Limits::DEFAULT)?;
    let e = SecretBox::from_value(&v).map_err(|_| Error::Malformed("entry box"))?;
    if e.to_value() != v {
        return Err(Error::Malformed("entry box"));
    }
    Ok(e)
}

fn ids(vs: Vec<Value>) -> Result<Vec<BlobId>, Error> {
    vs.into_iter().map(|v| dec::fixed(v, "blob id").map(BlobId)).collect()
}

fn ids_value(ids: &[BlobId]) -> Value {
    Value::List(ids.iter().map(|i| Value::bytes(&i.0)).collect())
}

fn labels(vs: Vec<Value>) -> Result<Vec<LabelId>, Error> {
    vs.into_iter().map(|v| dec::fixed(v, "label id").map(LabelId)).collect()
}

fn event(v: Value) -> Result<Event, Error> {
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
        (3, 1) => Event::Head(step(&mut f)?),
        (4, 2) => Event::Refused(BlobId(f.fixed()?), Code(f.uint()?)),
        _ => return Err(Error::Malformed("event")),
    };
    f.end()?;
    Ok(e)
}

pub(crate) fn event_value(e: &Event) -> Value {
    Value::List(match e {
        Event::Added { blob_id, blob, wrap, stamp } => vec![Value::uint(0), Value::bytes(&blob_id.0), Value::opt(blob.as_deref().map(Value::bytes)), Value::bytes(wrap), Value::opt(stamp.as_ref().map(|s| Value::bytes(&s.0)))],
        Event::Deleted(id) => vec![Value::uint(1), Value::bytes(&id.0)],
        Event::Full(full) => vec![Value::uint(2), Value::Bool(*full)],
        Event::Head(step) => vec![Value::uint(3), step_value(step)],
        Event::Refused(id, code) => vec![Value::uint(4), Value::bytes(&id.0), Value::uint(code.0)],
    })
}

fn opt_cursor(c: &Option<Vec<u8>>) -> Value {
    Value::opt(c.as_ref().map(|c| Value::bytes(c)))
}

fn opt_cursor_of(f: &mut Fields) -> Result<Option<Vec<u8>>, Error> {
    f.opt()?.map(|v| dec::bytes(v, crate::MAX_CURSOR_BYTES, "cursor")).transpose()
}

fn joins(vs: Vec<Value>) -> Result<Vec<Join>, Error> {
    vs.into_iter()
        .map(|v| {
            let mut g = Fields::exact(v, 2, "join")?;
            let l = LabelId(g.fixed()?);
            let c = opt_cursor_of(&mut g)?;
            g.end()?;
            Ok((l, c))
        })
        .collect()
}

fn joins_value(js: &[Join]) -> Value {
    Value::List(js.iter().map(|(l, c)| Value::List(vec![Value::bytes(&l.0), opt_cursor(c)])).collect())
}

fn stream_events(vs: Vec<Value>) -> Result<Vec<(LabelId, Event)>, Error> {
    vs.into_iter()
        .map(|v| {
            let mut g = Fields::exact(v, 2, "stream event")?;
            let l = LabelId(g.fixed()?);
            let e = event(g.next()?)?;
            g.end()?;
            Ok((l, e))
        })
        .collect()
}

fn stream_events_value(es: &[(LabelId, Event)]) -> Value {
    Value::List(es.iter().map(|(l, e)| Value::List(vec![Value::bytes(&l.0), event_value(e)])).collect())
}

/// Upper bound on the encoded size of a stream event (a Pull reply's paging).
pub fn stream_event_size(e: &Event) -> usize {
    event_size(e) + 24
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

/// Upper bound on the encoded size of an event (paging, spec/wire.md §11.2 `more`).
pub fn event_size(e: &Event) -> usize {
    match e {
        Event::Added { blob, .. } => 180 + blob.as_ref().map_or(0, |b| b.len()),
        Event::Deleted(_) | Event::Full(_) => 40,
        Event::Refused(..) => 50,
        Event::Head(_) => 10 + MAX_STEP_BYTES,
    }
}


#[cfg(test)]
mod tests;
