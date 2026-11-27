//! osis-proto: the node-to-node protocol's bytes (spec/wire.md §2, §11-§12): its limits, frames,
//! Hello, every message, connection proofs, the shared set's filter and the relay gate;
//! no session. Layer 5 (notes/architecture.md). Notes: notes/sync-protocol.md (osis-proto).
#![forbid(unsafe_code)]

pub mod api;
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

/// A sync ID: 16 bytes (spec/wire.md §1, §8).
pub use osis_base::SyncId;

pub use api::{ApiCode, Outcome, Payload};
pub use error::Error;
pub use frame::{FrameDecoder, encode_frame};
pub use hello::{ClockSamples, Hello, OFFSET_DIAGNOSTIC_MS, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
pub use msg::{Code, Cursor, DepositItem, Event, Fetched, Flow, Id, Join, Msg, OfferItem, Pull, PullReply, Rejected, SharedItem, SourceClass, Stamp, Stream, WantedItem, Wrap};
pub use prove::{Proof, Prover};
pub use relay::{RelayGate, RelayLimits, RelaySource, RelayVerdict};
