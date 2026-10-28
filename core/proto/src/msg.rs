//! Protocol version 1 messages (spec/wire.md §11.2) with their caps and limits (§13). Label
//! objects are osis-label's types (steps, claim sets, proofs, delete items, publish authorizations)
//! and the entry box is a `box` value; the wire carries steps, claim sets and boxes as their
//! canonical bytes.

use crate::Error;
use crate::dec::{self, Fields, b, opt_v, u};
use crate::rbsr::{self, Bound};
use osis_base::format::{MAX_BLOB, MAX_MESSAGE};
use osis_base::{BlobId, LabelId, Limits, Value, cbor};
pub use osis_crypto::Signature;
pub use osis_label::{ClaimSet, DeleteItem, Proof, PublishAuth, PublishKey, Step, StepId};
use osis_schema::Codec;
pub use osis_schema::core_types::SecretBox;

pub const WRAP_LEN: usize = osis_crypto::WRAP_LEN;
pub type Wrap = [u8; WRAP_LEN];

/// Per-message caps (spec/wire.md §11.2).
pub const MAX_ITEMS: usize = 1024;
pub const MAX_GAINED: usize = 4096;
pub const MAX_LABELS: usize = 1024;
pub const MAX_RECONCILE_RANGES: usize = 256;
pub const MAX_RECONCILE_REPLY_RANGES: usize = 4096;
pub const MAX_PATH_STEPS: usize = 1024;
/// Open labels per connection a peer may refuse to exceed (code 4).
pub const MAX_OPEN_LABELS: usize = 4096;
/// Signal envelope (spec/wire.md §13).
pub const MAX_SIGNAL: usize = osis_label::MAX_SIGNAL;
/// A canonical `Step` is at most this long (spec/wire.md §8: nine fixed-size items).
pub const MAX_STEP_BYTES: usize = 323;
/// Request ids are below 2^32 (spec/wire.md §11.1).
pub type Id = u32;

/// Deepest array nesting of any v1 message (FetchReply).
const MESSAGE_DEPTH: usize = 6;

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
    pub const CURSOR_INVALID: Code = Code(10);
    pub const UNSUPPORTED: Code = Code(11);
    pub const STORAGE_CAP: Code = Code(12);
    pub const UNKNOWN_LABEL: Code = Code(13);
}

/// `entry := [blob, wrap, stamp]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub blob: Vec<u8>,
    pub wrap: Wrap,
    pub stamp: Signature,
}

/// `cursor := [log_id, seq]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cursor {
    pub log_id: [u8; 16],
    pub seq: u64,
}

/// `event := [0, blob_id, Opt(blob), wrap, Opt(stamp)] | [1, blob_id] | [2, blob_id, at] | [3, step]`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // steps carry parsed keys; boxing buys nothing here
pub enum Event {
    /// Entry added or its wrap and stamp replaced; no stamp: deposited.
    Added { blob_id: BlobId, blob: Option<Vec<u8>>, wrap: Wrap, stamp: Option<Signature> },
    Deleted(BlobId),
    /// Timed deletion pending at `at`.
    Pending { blob_id: BlobId, at: u64 },
    /// New head, without claim set.
    Head(Step),
}

/// `range := [lower, upper, mode]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    pub lower: Bound,
    /// Empty: the end of the ID space.
    pub upper: Bound,
    pub mode: Mode,
}

/// `mode := [0, fingerprint] | [1, [blob_id*]] | [2, [blob_id*], [blob_id*]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Fingerprint([u8; 16]),
    /// The sender's IDs in the range, at most 32.
    Ids(Vec<BlobId>),
    /// The responder's IDs the list lacked (at most 1024), then the listed IDs it lacks.
    Diff { theirs: Vec<BlobId>, lacking: Vec<BlobId> },
}

/// A Fetch reply item: the entry of the label, or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    pub blob_id: BlobId,
    pub entry: Option<(Vec<u8>, Wrap, Option<Signature>)>,
}

/// Every v1 message after Hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Error { id: Id, code: Code },
    Ok { id: Id },
    Ping { id: Id, wall_ms: u64 },
    Pong { id: Id, wall_ms: u64 },
    Open { id: Id, label: LabelId, proof: Proof },
    Opened { id: Id, head: Step, entry_box: Option<SecretBox> },
    Step { id: Id, step: Step },
    Register { id: Id, label: LabelId, step: Step, claim_set: Option<ClaimSet> },
    Path { id: Id, label: LabelId, after: Option<StepId> },
    PathReply { id: Id, steps: Vec<Step>, more: bool },
    Upload { id: Id, label: LabelId, entries: Vec<Entry> },
    Status { id: Id, codes: Vec<Code>, head: Option<Step> },
    Deposit { id: Id, label: LabelId, blob: Vec<u8>, wrap: Wrap, sig: Signature },
    Budget { id: Id, code: Code, entries_left: u64, bytes_left: u64, head: Option<Step> },
    /// Items with `at` above 2^63 - 1 cannot be encoded (check with `osis_label::delete_digest`).
    Delete { id: Id, label: LabelId, items: Vec<DeleteItem> },
    Sync { id: Id, label: LabelId, cursor: Option<Cursor>, inline_limit: u64, entries: Vec<Entry>, gained: Vec<BlobId> },
    SyncReply { id: Id, events: Vec<Event>, want: Vec<BlobId>, codes: Vec<Code>, cursor: Cursor, more: bool },
    Reconcile { id: Id, label: LabelId, ranges: Vec<Range> },
    ReconcileReply { id: Id, ranges: Vec<Range> },
    Fetch { id: Id, label: LabelId, ids: Vec<BlobId> },
    FetchReply { id: Id, items: Vec<Fetched> },
    Subscribe { id: Id, labels: Vec<LabelId> },
    Unsubscribe { id: Id, labels: Vec<LabelId> },
    Push { label: LabelId, events: Vec<Event>, cursor: Cursor },
    Signal { label: LabelId, blob: Vec<u8>, wrap: Wrap, auth: PublishAuth },
}

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

/// Kinds that are requests (spec/wire.md §11.2: those with `->`).
pub fn is_request_kind(kind: u64) -> bool {
    matches!(kind, 2 | 4 | 7 | 8 | 10 | 12 | 14 | 15 | 17 | 19 | 21 | 22)
}

fn step_value(s: &Step) -> Value {
    b(&s.to_bytes())
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
            Open { .. } => 4,
            Opened { .. } => 5,
            Step { .. } => 6,
            Register { .. } => 7,
            Path { .. } => 8,
            PathReply { .. } => 9,
            Upload { .. } => 10,
            Status { .. } => 11,
            Deposit { .. } => 12,
            Budget { .. } => 13,
            Delete { .. } => 14,
            Sync { .. } => 15,
            SyncReply { .. } => 16,
            Reconcile { .. } => 17,
            ReconcileReply { .. } => 18,
            Fetch { .. } => 19,
            FetchReply { .. } => 20,
            Subscribe { .. } => 21,
            Unsubscribe { .. } => 22,
            Push { .. } => 23,
            Signal { .. } => 24,
        }
    }

    /// The request id (0 for Push and Signal).
    pub fn id(&self) -> Id {
        use Message::*;
        match self {
            Error { id, .. } | Ok { id } | Ping { id, .. } | Pong { id, .. } | Open { id, .. } | Opened { id, .. } | Step { id, .. } | Register { id, .. } | Path { id, .. } | PathReply { id, .. } | Upload { id, .. } | Status { id, .. } | Deposit { id, .. } | Budget { id, .. } | Delete { id, .. } | Sync { id, .. } | SyncReply { id, .. } | Reconcile { id, .. } | ReconcileReply { id, .. } | Fetch { id, .. } | FetchReply { id, .. } | Subscribe { id, .. } | Unsubscribe { id, .. } => *id,
            Push { .. } | Signal { .. } => 0,
        }
    }

    /// Whether this kind is a request the other side answers.
    pub fn is_request(&self) -> bool {
        is_request_kind(self.kind())
    }

    pub fn to_value(&self) -> Value {
        use Message as M;
        let k = u(self.kind());
        let id = u(self.id() as u64);
        let l = |x: &LabelId| b(&x.0);
        let items = match self {
            M::Error { code, .. } => vec![k, id, u(code.0)],
            M::Ok { .. } => vec![k, id],
            M::Ping { wall_ms, .. } | M::Pong { wall_ms, .. } => vec![k, id, u(*wall_ms)],
            M::Open { label, proof, .. } => vec![k, id, l(label), proof.to_value()],
            M::Opened { head, entry_box, .. } => vec![k, id, step_value(head), opt_v(entry_box.as_ref().map(|e| Value::Bytes(box_bytes(e))))],
            M::Step { step, .. } => vec![k, id, step_value(step)],
            M::Register { label, step, claim_set, .. } => vec![k, id, l(label), step_value(step), opt_v(claim_set.as_ref().map(|c| Value::Bytes(c.to_bytes())))],
            M::Path { label, after, .. } => vec![k, id, l(label), opt_v(after.as_ref().map(|a| b(&a.0)))],
            M::PathReply { steps, more, .. } => vec![k, id, Value::List(steps.iter().map(step_value).collect()), Value::Bool(*more)],
            M::Upload { label, entries, .. } => vec![k, id, l(label), entries_value(entries)],
            M::Status { codes, head, .. } => vec![k, id, codes_value(codes), opt_v(head.as_ref().map(step_value))],
            M::Deposit { label, blob, wrap, sig, .. } => vec![k, id, l(label), b(blob), b(wrap), b(&sig.0)],
            M::Budget { code, entries_left, bytes_left, head, .. } => vec![k, id, u(code.0), u(*entries_left), u(*bytes_left), opt_v(head.as_ref().map(step_value))],
            // An unencodable item (at above 2^63 - 1) becomes `[]`, which the peer rejects.
            M::Delete { label, items, .. } => vec![k, id, l(label), Value::List(items.iter().map(|i| i.to_value().unwrap_or(Value::List(vec![]))).collect())],
            M::Sync { label, cursor, inline_limit, entries, gained, .. } => vec![k, id, l(label), opt_v(cursor.as_ref().map(cursor_value)), u(*inline_limit), entries_value(entries), ids_value(gained)],
            M::SyncReply { events, want, codes, cursor, more, .. } => vec![k, id, events_value(events), ids_value(want), codes_value(codes), cursor_value(cursor), Value::Bool(*more)],
            M::Reconcile { label, ranges, .. } => vec![k, id, l(label), ranges_value(ranges)],
            M::ReconcileReply { ranges, .. } => vec![k, id, ranges_value(ranges)],
            M::Fetch { label, ids, .. } => vec![k, id, l(label), ids_value(ids)],
            M::FetchReply { items, .. } => vec![
                k,
                id,
                Value::List(
                    items
                        .iter()
                        .map(|f| {
                            let e = f.entry.as_ref().map(|(blob, wrap, stamp)| Value::List(vec![b(blob), b(wrap), opt_v(stamp.as_ref().map(|s| b(&s.0)))]));
                            Value::List(vec![b(&f.blob_id.0), opt_v(e)])
                        })
                        .collect(),
                ),
            ],
            M::Subscribe { labels, .. } | M::Unsubscribe { labels, .. } => vec![k, id, Value::List(labels.iter().map(l).collect())],
            M::Push { label, events, cursor } => vec![k, id, l(label), events_value(events), cursor_value(cursor)],
            M::Signal { label, blob, wrap, auth } => vec![k, id, l(label), b(blob), b(wrap), auth.to_value()],
        };
        Value::List(items)
    }

    /// The frame body. Callers keep it within `MAX_MESSAGE` (the engines page).
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    /// Decodes a frame body, enforcing every layout rule and cap of spec/wire.md §11.2, §13.
    pub fn decode(body: &[u8]) -> Result<Message, Rejected> {
        let v = cbor::decode(body, &Limits { max_depth: MESSAGE_DEPTH, max_bytes: MAX_MESSAGE }).map_err(|e| Rejected { kind: 0, id: 0, error: e.into() })?;
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
    let n = match kind {
        1 => 2,
        0 | 2 | 3 | 6 | 18 | 20 | 21 | 22 => 3,
        4 | 5 | 8 | 9 | 10 | 11 | 14 | 17 | 19 => 4,
        7 | 23 => 5,
        12 | 13 | 24 => 6,
        15 | 16 => 7,
        _ => return Err(Error::UnknownKind(kind)),
    };
    // Push and Signal have no reply (id 0); every request and reply has a real id; an Error
    // answering a broken frame may carry 0.
    match (kind, id) {
        (23 | 24, 0) | (0, _) => {}
        (23 | 24, _) => return Err(Error::Malformed("id of a message without reply")),
        (_, 0) => return Err(Error::Malformed("id 0")),
        _ => {}
    }
    let mut f = Fields::exact(v, n, "message")?;
    f.next()?;
    f.next()?;
    let msg = match kind {
        0 => Message::Error { id, code: Code(f.uint()?) },
        1 => Message::Ok { id },
        2 => Message::Ping { id, wall_ms: f.uint()? },
        3 => Message::Pong { id, wall_ms: f.uint()? },
        4 => Message::Open { id, label: label(&mut f)?, proof: Proof::from_value(&f.next()?)? },
        5 => Message::Opened { id, head: step(&mut f)?, entry_box: f.opt()?.map(entry_box).transpose()? },
        6 => Message::Step { id, step: step(&mut f)? },
        7 => Message::Register { id, label: label(&mut f)?, step: step(&mut f)?, claim_set: f.opt()?.map(claim_set).transpose()? },
        8 => Message::Path { id, label: label(&mut f)?, after: f.opt()?.map(|v| dec::fixed(v, "path after").map(StepId)).transpose()? },
        9 => {
            let steps = f.list(0, MAX_PATH_STEPS, "path steps")?.into_iter().map(step_of).collect::<Result<_, _>>()?;
            Message::PathReply { id, steps, more: f.bool()? }
        }
        10 => Message::Upload { id, label: label(&mut f)?, entries: entries(f.list(1, MAX_ITEMS, "upload entries")?)? },
        11 => Message::Status { id, codes: codes(f.list(1, usize::MAX, "status codes")?)?, head: f.opt()?.map(step_of).transpose()? },
        12 => Message::Deposit { id, label: label(&mut f)?, blob: f.bytes(MAX_BLOB)?, wrap: f.fixed()?, sig: Signature(f.fixed()?) },
        13 => Message::Budget { id, code: Code(f.uint()?), entries_left: f.uint()?, bytes_left: f.uint()?, head: f.opt()?.map(step_of).transpose()? },
        14 => {
            let label = label(&mut f)?;
            let items = f.list(1, MAX_ITEMS, "delete items")?.iter().map(DeleteItem::from_value).collect::<Result<_, _>>()?;
            Message::Delete { id, label, items }
        }
        15 => {
            let label = label(&mut f)?;
            let cursor = f.opt()?.map(cursor).transpose()?;
            let inline_limit = f.uint()?;
            let entries = entries(f.list(0, usize::MAX, "sync entries")?)?;
            let gained = ids(f.list(0, MAX_GAINED, "gained")?)?;
            Message::Sync { id, label, cursor, inline_limit, entries, gained }
        }
        16 => Message::SyncReply {
            id,
            events: events(f.list(0, usize::MAX, "events")?)?,
            want: ids(f.list(0, MAX_GAINED, "want")?)?,
            codes: codes(f.list(0, usize::MAX, "codes")?)?,
            cursor: cursor(f.next()?)?,
            more: f.bool()?,
        },
        17 => Message::Reconcile { id, label: label(&mut f)?, ranges: ranges(f.list(1, MAX_RECONCILE_RANGES, "ranges")?)? },
        18 => Message::ReconcileReply { id, ranges: ranges(f.list(0, MAX_RECONCILE_REPLY_RANGES, "ranges")?)? },
        19 => Message::Fetch { id, label: label(&mut f)?, ids: ids(f.list(1, MAX_ITEMS, "fetch ids")?)? },
        20 => Message::FetchReply { id, items: f.list(0, MAX_ITEMS, "fetch items")?.into_iter().map(fetched).collect::<Result<_, _>>()? },
        21 => Message::Subscribe { id, labels: labels(f.list(1, MAX_LABELS, "labels")?)? },
        22 => Message::Unsubscribe { id, labels: labels(f.list(1, MAX_LABELS, "labels")?)? },
        23 => Message::Push { label: label(&mut f)?, events: events(f.list(1, usize::MAX, "events")?)?, cursor: cursor(f.next()?)? },
        24 => Message::Signal { label: label(&mut f)?, blob: f.bytes(MAX_SIGNAL)?, wrap: f.fixed()?, auth: PublishAuth::from_value(&f.next()?)? },
        _ => return Err(Error::UnknownKind(kind)),
    };
    f.end()?;
    Ok(msg)
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

fn entries(vs: Vec<Value>) -> Result<Vec<Entry>, Error> {
    vs.into_iter()
        .map(|v| {
            let mut f = Fields::exact(v, 3, "entry")?;
            let e = Entry { blob: f.bytes(MAX_BLOB)?, wrap: f.fixed()?, stamp: Signature(f.fixed()?) };
            f.end()?;
            Ok(e)
        })
        .collect()
}

fn entries_value(es: &[Entry]) -> Value {
    Value::List(es.iter().map(|e| Value::List(vec![b(&e.blob), b(&e.wrap), b(&e.stamp.0)])).collect())
}

fn cursor(v: Value) -> Result<Cursor, Error> {
    let mut f = Fields::exact(v, 2, "cursor")?;
    let c = Cursor { log_id: f.fixed()?, seq: f.uint()? };
    f.end()?;
    Ok(c)
}

fn cursor_value(c: &Cursor) -> Value {
    Value::List(vec![b(&c.log_id), u(c.seq)])
}

fn ids(vs: Vec<Value>) -> Result<Vec<BlobId>, Error> {
    vs.into_iter().map(|v| dec::fixed(v, "blob id").map(BlobId)).collect()
}

fn ids_value(ids: &[BlobId]) -> Value {
    Value::List(ids.iter().map(|i| b(&i.0)).collect())
}

fn labels(vs: Vec<Value>) -> Result<Vec<LabelId>, Error> {
    vs.into_iter().map(|v| dec::fixed(v, "label id").map(LabelId)).collect()
}

fn codes(vs: Vec<Value>) -> Result<Vec<Code>, Error> {
    vs.into_iter().map(|v| dec::uint(v, "code").map(Code)).collect()
}

fn codes_value(cs: &[Code]) -> Value {
    Value::List(cs.iter().map(|c| u(c.0)).collect())
}

fn events(vs: Vec<Value>) -> Result<Vec<Event>, Error> {
    vs.into_iter().map(event).collect()
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
        (2, 2) => Event::Pending { blob_id: BlobId(f.fixed()?), at: f.uint()? },
        (3, 1) => Event::Head(step(&mut f)?),
        _ => return Err(Error::Malformed("event")),
    };
    f.end()?;
    Ok(e)
}

pub(crate) fn event_value(e: &Event) -> Value {
    Value::List(match e {
        Event::Added { blob_id, blob, wrap, stamp } => vec![u(0), b(&blob_id.0), opt_v(blob.as_deref().map(b)), b(wrap), opt_v(stamp.as_ref().map(|s| b(&s.0)))],
        Event::Deleted(id) => vec![u(1), b(&id.0)],
        Event::Pending { blob_id, at } => vec![u(2), b(&blob_id.0), u(*at)],
        Event::Head(step) => vec![u(3), step_value(step)],
    })
}

fn events_value(es: &[Event]) -> Value {
    Value::List(es.iter().map(event_value).collect())
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

fn ranges(vs: Vec<Value>) -> Result<Vec<Range>, Error> {
    let mut out: Vec<Range> = Vec::with_capacity(vs.len());
    for v in vs {
        let mut f = Fields::exact(v, 3, "range")?;
        let lower = Bound::new(f.bytes(32)?).ok_or(Error::Malformed("bound"))?;
        let upper = Bound::new(f.bytes(32)?).ok_or(Error::Malformed("bound"))?;
        if !rbsr::lower_below_upper(&lower, &upper) {
            return Err(Error::Malformed("range bounds"));
        }
        if let Some(prev) = out.last()
            && (prev.upper.is_end() || rbsr::cmp_bounds(&prev.upper, &lower) == std::cmp::Ordering::Greater)
        {
            return Err(Error::Malformed("ranges unsorted or overlapping"));
        }
        let mut m = Fields::range(f.next()?, 2, 3, "mode")?;
        let in_range = |ids: &[BlobId]| ids.is_sorted_by(|a, b| a < b) && ids.iter().all(|i| rbsr::contains(&lower, &upper, i));
        let mode = match (m.uint()?, m.remaining()) {
            (0, 1) => Mode::Fingerprint(m.fixed()?),
            (1, 1) => Mode::Ids(ids(m.list(0, rbsr::LIST_MAX, "mode 1 ids")?)?),
            (2, 2) => Mode::Diff { theirs: ids(m.list(0, rbsr::DIFF_MAX, "mode 2 ids")?)?, lacking: ids(m.list(0, rbsr::LIST_MAX, "mode 2 ids")?)? },
            _ => return Err(Error::Malformed("mode")),
        };
        m.end()?;
        f.end()?;
        let ok = match &mode {
            Mode::Fingerprint(_) => true,
            Mode::Ids(ids) => in_range(ids),
            Mode::Diff { theirs, lacking } => in_range(theirs) && in_range(lacking),
        };
        if !ok {
            return Err(Error::Malformed("mode ids unsorted or outside the range"));
        }
        out.push(Range { lower, upper, mode });
    }
    Ok(out)
}

fn ranges_value(rs: &[Range]) -> Value {
    Value::List(
        rs.iter()
            .map(|r| {
                let mode = match &r.mode {
                    Mode::Fingerprint(fp) => vec![u(0), b(fp)],
                    Mode::Ids(ids) => vec![u(1), ids_value(ids)],
                    Mode::Diff { theirs, lacking } => vec![u(2), ids_value(theirs), ids_value(lacking)],
                };
                Value::List(vec![b(r.lower.as_bytes()), b(r.upper.as_bytes()), Value::List(mode)])
            })
            .collect(),
    )
}

/// Upper bound on the encoded size of an event (paging, spec/wire.md §11.2 `more`).
pub fn event_size(e: &Event) -> usize {
    match e {
        Event::Added { blob, .. } => 180 + blob.as_ref().map_or(0, |b| b.len()),
        Event::Deleted(_) => 40,
        Event::Pending { .. } => 50,
        Event::Head(_) => 10 + MAX_STEP_BYTES,
    }
}

/// Upper bound on the encoded size of an entry.
pub fn entry_size(e: &Entry) -> usize {
    140 + e.blob.len()
}

#[cfg(test)]
mod tests;
