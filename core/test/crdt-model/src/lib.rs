//! Reference model for spec/crdt.md. Slow and small on purpose; the real implementation is tested against it.
pub mod cbor;
pub mod diff;
pub mod embed;
pub mod gen;
pub mod ops;
pub mod received;
pub mod seq;
pub mod stamp;
pub mod state;
pub mod value;
pub mod wire;
