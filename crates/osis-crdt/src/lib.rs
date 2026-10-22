//! osis-crdt: merge encodings: state, delta grammar, join, read, diff, paging (spec/crdt.md).
//! Defines `View`, `PageSink`, `PageSource`. Sequences in `seq`.
//! Layer 1 (notes/architecture.md). Notes: notes/crdt.md (Implementation).
#![forbid(unsafe_code)]

mod access;
mod batch;
mod changes;
mod codec;
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
mod seq_span;
mod seq_wire;
mod stamp;
mod state;
mod undo;
mod view;
mod wire;

#[cfg(test)]
mod testutil;
#[cfg(test)]
mod tests_join;
#[cfg(test)]
mod tests_wire;
#[cfg(test)]
mod tests_ops;
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
pub use codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot, page_array};
pub use error::Error;
pub use fragment::{BagKind, Bag, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
pub use shape::Shown;
pub use batch::Batch;
pub use ops::{Op, PathOp, PathSeg, Writer, create, diff, diff_values, remove, replace, reset_entries};
pub use undo::{UndoBuffer, Undone, undo};
pub use page::{MemoryPages, PageError, PageParams, PageSink, PageSource};
pub use paging::{PagedTouch, Paths, Step};
pub use state::MemberRef;
pub use seq::{Anchor, Seq, SeqContent, SeqElem};
pub use seq_ops::cut_dots;
pub use stamp::{CounterRange, Dot, Interner, Source, SourceKind, Stamp};
pub use view::{AnyView, View};
pub use lifecycle::{unmerge, unmerge_in_place};
pub use wire::{Dec, Delta, DeltaCtx, DeltaKind, Enc, Frontiers, Received, MAX_RUN, NONCE_LEN, Snapshot};
