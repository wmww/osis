//! osis-proto: the node-to-node sync protocol (spec/sync.md §5-§9, §11; spec/wire.md §11-§13):
//! frames, Hello, every message, range reconciliation, and sans-I/O client and server engines
//! (`handle(now, Input) -> Vec<Output>`; no async, no sockets, time passed in).
//! Layer 5 (notes/architecture.md). Plan: plans/proto.md.
#![forbid(unsafe_code)]

mod dec;
mod error;
pub mod frame;
pub mod hello;

pub use error::Error;
pub use frame::{FrameDecoder, encode_frame};
pub use hello::{Hello, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
