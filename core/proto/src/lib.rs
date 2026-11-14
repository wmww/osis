//! osis-proto: the node-to-node protocol's bytes (spec/wire.md §2, §11-§13): its limits, frames,
//! Hello, every message, actor proofs, the shared set's filter, bundle import and the relay gate;
//! no session. Layer 5 (notes/architecture.md). Notes: notes/sync-protocol.md (osis-proto).
#![forbid(unsafe_code)]

pub mod api;
pub mod bundle;
mod dec;
mod error;
#[doc(hidden)]
pub mod examples;
pub mod filter;
pub mod frame;
pub mod hello;
pub mod limits;
pub mod msg;
pub mod prove;
pub mod relay;

/// A sync ID: 16 bytes (spec/wire.md §1, §8). osis-base still names the type `LabelId`
/// (issues/deprecated-terms.md, label); sync code says `SyncId`.
pub use osis_base::LabelId as SyncId;

pub use api::{ApiCode, Outcome, Payload};
pub use error::Error;
pub use frame::{FrameDecoder, encode_frame};
pub use hello::{ClockSamples, Hello, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
pub use msg::{BehindItem, Code, Cursor, DepositItem, Event, Fetched, Flow, Grant, Id, Join, Msg, OfferItem, Pull, PullReply, Rejected, SharedItem, Stamp, Stream, SuspectEntry, Wrap};
pub use prove::{ActorProof, Prover};
pub use relay::{RelayGate, RelayLimits, RelayVerdict};
