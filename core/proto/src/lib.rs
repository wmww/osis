//! osis-proto: the node-to-node protocol's bytes (spec/wire.md §11-§13): frames, Hello, every
//! message, actor proofs, the shared-set filter, bundles and the relay gate; no session.
//! Layer 5 (notes/architecture.md). Notes: notes/sync-protocol.md (osis-proto).
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
pub mod msg;
pub mod prove;
pub mod relay;

pub use api::{ApiCode, MAX_SUBS, Outcome, Payload};
pub use error::Error;
pub use relay::{RelayGate, RelayLimits, RelayVerdict};
pub use frame::{FrameDecoder, MAX_HELLO_BYTES, encode_frame};
pub use hello::{ClockSamples, Hello, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
pub use prove::{ActorProof, MAX_PROOFS, MAX_RESUME_TAGS, Prover};
pub use msg::{Code, Event, Fetched, Message, Rejected};

/// Longest opaque node-log cursor a `Lost` carries (`osis_store` seals one in 80 bytes or so).
pub const MAX_CURSOR_BYTES: usize = 256;
