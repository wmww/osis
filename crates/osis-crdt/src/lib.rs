//! osis-crdt: merge encodings: state, delta grammar, join, read, diff, paging (spec/crdt.md).
//! Defines `View`, `PageSink`, `PageSource`. Sequences (`seq`) are plans/crdt-seq.md's.
//! Layer 1 (notes/architecture.md). Plans: plans/crdt-core.md, plans/crdt-seq.md.
#![forbid(unsafe_code)]
// Skeleton (crdt-core step 1): hooks and helpers are wired by later steps.
#![allow(dead_code)]

mod changes;
mod codec;
mod error;
mod fragment;
mod ops;
mod page;
mod seq;
mod stamp;
mod state;
mod view;
mod wire;

#[cfg(test)]
mod testutil;
#[cfg(test)]
mod tests_join;
#[cfg(test)]
mod tests_wire;

pub use changes::{Changes, Death};
pub use codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
pub use error::Error;
pub use fragment::{BagKind, Bag, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
pub use ops::Writer;
pub use page::{MemoryPages, PageError, PageSink, PageSource};
pub use state::MemberRef;
pub use seq::{Anchor, Seq, SeqContent, SeqElem};
pub use stamp::{CounterRange, Dot, Interner, Source, SourceKind, Stamp};
pub use view::{AnyView, View};
pub use wire::{Dec, Delta, DeltaCtx, DeltaKind, Enc, Frontiers, MAX_RUN, NONCE_LEN, Snapshot};
