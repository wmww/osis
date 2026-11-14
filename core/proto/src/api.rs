//! Client-port messages (spec/wire.md §11.2 kinds 24-29; notes/client-port.md §2): API calls and
//! subscriptions on the same connection as sync. The protocol carries `args`, results, filters
//! and deliveries as opaque values, each at most `MAX_VALUE_DEPTH` deep; their meaning is the
//! method table's (notes/client-port.md). Here: the reply outcome, the Notify payload, the API
//! error codes.

use crate::Error;
use crate::dec::Fields;
use osis_base::Value;
use osis_base::format::MAX_VALUE_DEPTH;

/// An embedded value: at most `MAX_VALUE_DEPTH` deep (spec/wire.md §13).
fn value(v: Value) -> Result<Value, Error> {
    if v.deeper_than(MAX_VALUE_DEPTH) {
        return Err(Error::Malformed("value too deep"));
    }
    Ok(v)
}

/// A Reply's outcome: `[0, value] | [1, code, detail*]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok { value: Value },
    /// An API error (`code` from `ApiCode`) with its details.
    Err { code: u64, detail: Vec<Value> },
}

impl Outcome {
    pub fn to_value(&self) -> Value {
        match self {
            Outcome::Ok { value } => Value::List(vec![Value::uint(0), value.clone()]),
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
                let value = value(f.next()?)?;
                f.end()?;
                Outcome::Ok { value }
            }
            1 => {
                let code = f.uint()?;
                let mut detail = Vec::new();
                while f.remaining() > 0 {
                    detail.push(value(f.next()?)?);
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

/// A Notify payload: `[0, delivery] | [1] | [2, source]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Delivery { value: Value },
    /// The subscription ended at the node (its id is free again); subscribe again.
    Lapsed,
    /// A delivery above the subscription's `max_reply`: what changed, to be read by path or
    /// `stream_read`.
    TooLarge { source: Value },
}

impl Payload {
    pub fn to_value(&self) -> Value {
        Value::List(match self {
            Payload::Delivery { value } => vec![Value::uint(0), value.clone()],
            Payload::Lapsed => vec![Value::uint(1)],
            Payload::TooLarge { source } => vec![Value::uint(2), source.clone()],
        })
    }

    pub(crate) fn from_value(v: Value) -> Result<Payload, Error> {
        let mut f = Fields::range(v, 1, 2, "notify payload")?;
        let p = match (f.uint()?, f.remaining()) {
            (0, 1) => Payload::Delivery { value: value(f.next()?)? },
            (1, 0) => Payload::Lapsed,
            (2, 1) => Payload::TooLarge { source: value(f.next()?)? },
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
    /// `[path, text]`
    pub const TYPE: u64 = 4;
    /// `[limit]`
    pub const TOO_LARGE: u64 = 5;
    /// `[commit, reason]`
    pub const NOT_UNDOABLE: u64 = 6;
    /// `[[tid*]]`
    pub const UNSYNCED: u64 = 7;
    /// `[text]`
    pub const INVALID: u64 = 8;
    /// `[text]`
    pub const STORAGE: u64 = 9;
    /// `[text]`
    pub const NETWORK: u64 = 10;
    /// `[text]`; an unknown method too.
    pub const UNSUPPORTED: u64 = 11;
    /// No detail: the write may or may not have applied.
    pub const OUTCOME_UNKNOWN: u64 = 12;
    /// `[text]`: this session may not use the node.
    pub const REFUSED: u64 = 13;
    /// No detail: the node closed while the call was in hand.
    pub const CLOSED: u64 = 14;
    /// No detail: the node's store is open elsewhere.
    pub const IN_USE: u64 = 15;
}
