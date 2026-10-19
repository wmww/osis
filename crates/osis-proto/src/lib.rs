//! osis-proto: the node-to-node sync protocol (spec/sync.md §5-§9, §11; spec/wire.md §11-§13):
//! frames, Hello, every message, range reconciliation, and sans-I/O client and server engines
//! (`handle(now, Input) -> Vec<Output>`; no async, no sockets, time passed in).
//! Layer 5 (notes/architecture.md). Plan: plans/proto.md.
#![forbid(unsafe_code)]

pub mod bundle;
pub mod client;
mod dec;
mod error;
#[doc(hidden)]
pub mod examples;
pub mod frame;
pub mod hello;
pub mod label;
pub mod msg;
pub mod rbsr;
pub mod server;
pub mod store;

pub use client::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command, OpenKey};
pub use error::Error;
pub use server::{ServerConfig, ServerConnection, ServerInput, ServerOutput};
pub use store::{Budget, EntryMeta, LabelStore, LogRecord, MemoryLabelStore, Put, StoreError, StoredStep};
pub use frame::{FrameDecoder, encode_frame};
pub use hello::{Hello, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
pub use msg::{Code, Cursor, DeleteItem, Entry, Event, Fetched, Message, Mode, Proof, Range, Rejected, SignalAuth};
