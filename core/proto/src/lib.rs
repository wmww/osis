//! osis-proto: the node-to-node sync protocol (spec/sync-ids.md §6; spec/wire.md §11-§13):
//! frames, Hello, every message, and the sans-I/O session of one connection, either side
//! (`handle(now, store, Input) -> Vec<Output>`; no async, no sockets, time passed in).
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
pub mod session;
pub mod store;
pub mod window;

pub use api::{ApiCode, MAX_SUBS, Outcome, Payload};
pub use error::Error;
pub use session::{Relayed, Session, SessionConfig, SessionInput, SessionOutput};
pub use relay::{RelayGate, RelayLimits, RelayVerdict};
pub use store::{EntryMeta, HeadKeys, LabelStore, MemoryLabelStore, Put, StepKey, StoreError};
pub use frame::{FrameDecoder, MAX_HELLO_BYTES, encode_frame};
pub use hello::{ClockSamples, Hello, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
pub use prove::{ActorProof, MAX_PROOFS, MAX_RESUME_TAGS, Prover};
pub use msg::{Code, Event, Fetched, Message, Rejected};

/// Longest opaque node-log cursor a `Lost` carries (`osis_store` seals one in 80 bytes or so).
pub const MAX_CURSOR_BYTES: usize = 256;
