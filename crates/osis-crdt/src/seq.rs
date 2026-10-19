//! Sequences: list (8) and text (9) (spec/crdt.md §5.7, §6). State types are declared here; the
//! behaviour is plans/crdt-seq.md's. The generic code calls only the hooks below, so crdt-seq
//! fills this module (and adds its own) without touching the others. Until then decoding,
//! creating or diffing a sequence fails with `Error::Unsupported`, so no non-empty `Seq` reaches
//! a state and the state hooks below are never asked to do real work.
//!
//! Hook contract: the generic code owns `Seq::meta` (reset, `W`): it joins and prunes them and
//! passes the effective reset `e` (§4.2, already including the sequence's own reset) to the
//! element hooks. Nested list content recurses through `Fragment::join_into`, `Fragment::prune`,
//! `Fragment::read`, `Enc::fragment`, `Dec::fragment`. Deaths and changes go to `Changes`.

use crate::changes::Changes;
use crate::error::Error;
use crate::fragment::{Encoding, Fragment, Meta, Register};
use crate::ops::{Op, PathOp, PathSeg, Writer};
use crate::stamp::{Dot, Source, Stamp};
use crate::view::View;
use crate::wire::{Dec, Enc};
use osis_core::Value;
use std::collections::BTreeMap;

/// `HEAD` or an element's dot (§3.2 `Anchor`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor {
    Head,
    Dot(Dot),
}

/// An element's content: text, one char; list, a fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeqContent {
    None,
    Char(char),
    Frag(Box<Fragment>),
}

/// One element record (§5.7 State), identified by its creation dot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqElem {
    /// The creation write `(stamp, anchor)`; text content lives and dies with it.
    pub(crate) created: Option<(Stamp, Anchor)>,
    pub(crate) content: SeqContent,
    /// The two greatest position writes, creation included, greatest first.
    pub(crate) pos: Vec<(Stamp, Anchor)>,
    /// Text: the deleted flag (LWW bool). List: the element reset, always `true`.
    pub(crate) deleted: Option<(Stamp, bool)>,
}

/// A list or text fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seq {
    pub(crate) text: bool,
    pub(crate) meta: Meta,
    pub(crate) elems: BTreeMap<Dot, SeqElem>,
}

impl Seq {
    pub fn empty(text: bool) -> Seq {
        Seq { text, meta: Meta::default(), elems: BTreeMap::new() }
    }
    pub fn encoding(&self) -> Encoding {
        if self.text { Encoding::Text } else { Encoding::List }
    }
}

const UNSUPPORTED: Error = Error::Unsupported("sequences (plans/crdt-seq.md)");

// ---- state hooks (§4, §5.7)

/// Joins `d`'s element records into `s` and prunes what lands against `e`.
pub(crate) fn join_elems(_s: &mut Seq, _d: Seq, _e: Option<&Stamp>, _ch: &mut Changes) {}

/// Prunes every element record under effective reset `e` (records are never removed, §4.2).
pub(crate) fn prune_elems(_s: &mut Seq, _e: Option<&Stamp>, _ch: &mut Changes) {}

/// Greatest stamp inside the elements; with `valued`, only presence-counting writes (§4.3).
pub(crate) fn inner_max(_s: &Seq, _valued: bool) -> Option<Stamp> {
    None
}

/// Whether any record exists (emptiness, §4.2).
pub(crate) fn has_records(s: &Seq) -> bool {
    !s.elems.is_empty()
}

/// The read of a present sequence: string or list (§5.7 Read, §6).
pub(crate) fn read(_s: &Seq) -> Option<Value> {
    None
}

/// Holds value-carrying writes of expired deltas value-less (§4.7); `expired` gets owner dots.
pub(crate) fn strip_values(_s: &mut Seq, _expired: &dyn Fn(&Dot) -> bool) {}

/// Removes every write whose dot's author matches (un-merge, §4.6); records stay as anchors.
pub(crate) fn remove_author(_s: &mut Seq, _author: &dyn Fn(&Source) -> bool) {}

/// Elements of the embedding of register `r` into a text slot (§7); the caller sets the reset.
pub(crate) fn embed_text(_r: &Register) -> BTreeMap<Dot, SeqElem> {
    BTreeMap::new()
}

// ---- wire hooks (§3.2 Run, §3.3)

/// The `[Run*]` array of `s` (before paging). Sort runs with `Enc::dot_order`.
pub(crate) fn encode_elems(_s: &Seq, _cx: &mut Enc) -> Result<Vec<Value>, Error> {
    Err(UNSUPPORTED)
}

/// Reads runs (one page or the whole array) into `s`.
pub(crate) fn decode_elems(_s: &mut Seq, _runs: &[Value], _cx: &mut Dec) -> Result<(), Error> {
    Err(UNSUPPORTED)
}

// ---- op hooks (§5.7 Ops, §9)

/// A fresh sequence holding `v` (a string or list) as a creation run.
pub(crate) fn create<V: View>(_w: &mut Writer, _text: bool, _view: &V, _v: &Value) -> Result<Seq, Error> {
    Err(UNSUPPORTED)
}

/// Structural diff of present state `s` against `v` (§9 list, text); `None` when nothing changes.
pub(crate) fn diff<V: View>(_w: &mut Writer, _s: &Seq, _view: &V, _v: &Value) -> Result<Option<Seq>, Error> {
    Err(UNSUPPORTED)
}

/// Sequence op (insert, delete, move) against present state `s` (§5.7 Ops); `None` if a no-op.
pub(crate) fn op<V: View>(_w: &mut Writer, _text: bool, _s: Option<&Seq>, _view: &V, _op: &Op) -> Result<Option<Seq>, Error> {
    Err(UNSUPPORTED)
}

/// The visible element at index `i`: its dot and, for a list, its content fragment.
pub(crate) fn element_at(_s: &Seq, _i: usize) -> Option<(Dot, Option<Fragment>)> {
    None
}

/// A list delta carrying `content` (a nested delta) on existing element `d` (§5.7 element edits).
pub(crate) fn wrap_element(d: Dot, content: Fragment) -> Seq {
    let el = SeqElem { created: None, content: SeqContent::Frag(Box::new(content)), pos: Vec::new(), deleted: None };
    Seq { text: false, meta: Meta::default(), elems: BTreeMap::from([(d, el)]) }
}

/// Merges `d`, a later op of the same commit, into `acc` (§4.5 net effect: an element created
/// and removed in the commit is omitted and anchors naming it are rewritten). `w.made(dot)`
/// tells elements created by this commit.
pub(crate) fn overlay(_acc: Seq, d: Seq, _w: &Writer) -> Seq {
    d
}

/// Undo of a sequence delta (§4.6, §5.7 Undo); `made` tells elements the undone commit created.
pub(crate) fn undo<V: View>(_w: &mut Writer, _undone: &Seq, _cur: Option<&Seq>, _made: &dyn Fn(&Dot) -> bool, _view: &V) -> Result<Option<Seq>, Error> {
    Err(UNSUPPORTED)
}

/// The ops turning sequence value `base` into `new` at `path` (notes/api.md `edit`); until
/// crdt-seq, the whole new value by structural diff.
pub(crate) fn diff_values<V: View>(_base: &Value, new: &Value, _view: &V, path: &[PathSeg]) -> Result<Vec<PathOp>, Error> {
    Ok(vec![PathOp { path: path.to_vec(), op: Op::Set(new.clone()) }])
}
