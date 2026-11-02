//! Client-port messages (spec/wire.md §11.2 kinds 24-29; notes/client-port.md §2): API calls and
//! subscriptions on the same connection as sync. The protocol carries `args`, results, filters
//! and deliveries as opaque values; their meaning is the `osis` crate's (`osis::port`). Here: the
//! reply outcome, the Notify payload, the API error codes, the subscription cap.

use crate::Error;
use crate::dec::Fields;
use osis_base::Value;

pub use crate::client::SMALL_REPLY;
pub use crate::serving::REPLY_BUDGET;

/// Subscriptions per connection, counted apart from open labels (code 4 past it). Resource
/// bound: each holds a dirty flag and a filter at the serving side; 0 forbids watching remotely,
/// infinity lets one connection grow the dirty-flag table and the per-change filter walk without
/// bound.
pub const MAX_SUBS: usize = 4096;

/// A Reply's outcome: `[0, seq, value] | [1, code, detail*]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `seq`: the node's change sequence when the call ran (a client settles up to it).
    Ok { seq: u64, value: Value },
    /// An API error (`code` from `ApiCode`) with its details.
    Err { code: u64, detail: Vec<Value> },
}

impl Outcome {
    pub fn to_value(&self) -> Value {
        match self {
            Outcome::Ok { seq, value } => Value::List(vec![Value::uint(0), Value::uint(*seq), value.clone()]),
            Outcome::Err { code, detail } => {
                let mut v = vec![Value::uint(1), Value::uint(*code)];
                v.extend(detail.iter().cloned());
                Value::List(v)
            }
        }
    }

    pub(crate) fn from_value(v: Value) -> Result<Outcome, Error> {
        let mut f = Fields::range(v, 2, usize::MAX, "reply outcome")?;
        Ok(match f.uint()? {
            0 => {
                let seq = f.uint()?;
                let value = f.next()?;
                f.end()?;
                Outcome::Ok { seq, value }
            }
            1 => {
                let code = f.uint()?;
                let mut detail = Vec::new();
                while f.remaining() > 0 {
                    detail.push(f.next()?);
                }
                Outcome::Err { code, detail }
            }
            _ => return Err(Error::Malformed("reply outcome")),
        })
    }

    /// The `TooLarge` error for a reply that does not fit `limit`.
    pub fn too_large(limit: usize) -> Outcome {
        Outcome::Err { code: ApiCode::TOO_LARGE, detail: vec![Value::uint(limit as u64)] }
    }
}

/// A Notify payload: `[0, seq, delivery] | [1] | [2, seq, source]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// A delivery after the node's change `seq`.
    Delivery { seq: u64, value: Value },
    /// The subscription ended at the node (its id is free again); subscribe again.
    Lapsed,
    /// A delivery above the subscription's `max_reply`: what changed, to be read by path or
    /// `stream_read`.
    TooLarge { seq: u64, source: Value },
}

impl Payload {
    pub fn to_value(&self) -> Value {
        Value::List(match self {
            Payload::Delivery { seq, value } => vec![Value::uint(0), Value::uint(*seq), value.clone()],
            Payload::Lapsed => vec![Value::uint(1)],
            Payload::TooLarge { seq, source } => vec![Value::uint(2), Value::uint(*seq), source.clone()],
        })
    }

    pub(crate) fn from_value(v: Value) -> Result<Payload, Error> {
        let mut f = Fields::range(v, 1, 3, "notify payload")?;
        let p = match (f.uint()?, f.remaining()) {
            (0, 2) => Payload::Delivery { seq: f.uint()?, value: f.next()? },
            (1, 0) => Payload::Lapsed,
            (2, 2) => Payload::TooLarge { seq: f.uint()?, source: f.next()? },
            _ => return Err(Error::Malformed("notify payload")),
        };
        f.end()?;
        Ok(p)
    }
}

/// API error codes of a Reply `[1, code, detail*]` (spec/wire.md §11.2), one per `osis::Error`
/// variant that crosses the port.
pub struct ApiCode;

impl ApiCode {
    /// `[tid]`
    pub const UNKNOWN_THING: u64 = 1;
    /// `[tid]`
    pub const UNKNOWN_ACTOR: u64 = 2;
    /// `[tid, role]`
    pub const PERMISSION: u64 = 3;
    /// `[path, reason]`
    pub const TYPE: u64 = 4;
    /// `[limit]`
    pub const TOO_LARGE: u64 = 5;
    /// `[change, reason]`
    pub const NOT_UNDOABLE: u64 = 6;
    /// `[[tid*]]`
    pub const UNSYNCED: u64 = 7;
    /// `[text]`
    pub const INVALID: u64 = 8;
    pub const STORAGE: u64 = 9;
    pub const NETWORK: u64 = 10;
    pub const UNSUPPORTED: u64 = 11;
    /// No detail: the write may or may not have applied.
    pub const OUTCOME_UNKNOWN: u64 = 12;
}
