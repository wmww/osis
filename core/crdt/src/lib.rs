//! osis-crdt: merge encodings: state, delta grammar, join, read, diff, paging (spec/crdt.md).
//! Defines `View`, `PageSink`, `PageSource`. Sequences in `seq`.
//! Layer 1 (notes/architecture.md). Notes: notes/crdt.md (Implementation).
#![forbid(unsafe_code)]

mod access;
mod batch;
mod changes;
mod codec;
mod copies;
mod error;
mod fragment;
#[doc(hidden)]
pub mod fuzzing;
mod lifecycle;
mod linearize;
mod ops;
mod page;
mod paging;
mod remap;
mod seq;
mod shape;
mod seq_diff;
mod seq_lin;
mod seq_ops;
mod seq_place;
mod seq_span;
mod seq_wire;
mod stamp;
mod state;
mod undo;
mod view;
mod wire;

// test support, also built for the fuzz targets (`--cfg fuzzing`, core/test/fuzz); test code
// for clippy's no-panic lints, which see only `cfg(test)`
#[cfg(any(test, fuzzing))]
#[cfg_attr(fuzzing, allow(dead_code))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod testutil;
#[cfg(any(test, fuzzing))]
#[cfg_attr(fuzzing, allow(dead_code))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod fuzz_seq;
#[cfg(test)]
mod tests_join;
#[cfg(test)]
mod tests_wire;
#[cfg(test)]
mod tests_ops;
#[cfg(test)]
mod tests_undo;
#[cfg(test)]
mod tests_life;
#[cfg(test)]
mod tests_laws;
#[cfg(test)]
mod tests_review;
#[cfg(test)]
mod tests_seq;
#[cfg(test)]
mod tests_seq_ops;
#[cfg(test)]
mod tests_decoder;

pub use changes::{Changes, Death};
pub use copies::CopyIndex;
pub use codec::{decoded_bound, decode_delta, decode_snapshot, encode_delta, encode_snapshot, page_array};
pub use error::Error;
pub use fragment::{BagKind, Bag, CaseWrite, Eid, Elem, Encoding, Entry, Key, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
pub use shape::Shown;
pub use batch::Batch;
pub use ops::{Op, PathOp, PathSeg, Writer, create, diff, diff_values, remove, replace, reset_entries};
pub use undo::{UndoBuffer, Undone, undo};
pub use page::{MemoryPages, PageError, PageParams, PageSink, PageSource, Unpaged};
pub use paging::{PagedTouch, Paths, Step};
pub use state::MemberRef;
pub use seq::{Anchor, Seq, SeqContent, SeqElem};
pub use seq_diff::{EditWindow, changes, edit_window};
pub use seq_ops::cut_dots;
pub use seq_place::{PlaceBlock, PlaceDiff, PlaceMisses, PlaceRow, PlaceTop, SeqPlace};
pub use lifecycle::Stamps;
pub use stamp::{CounterRange, Dot, Interner, Source, SourceKind, Stamp};
pub use view::{AnyView, View};
pub use wire::{Dec, Delta, DeltaCtx, DeltaKind, Enc, Frontiers, Received, MAX_RUN, NONCE_LEN, Snapshot};
