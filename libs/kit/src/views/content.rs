//! The view types that are a stack of facets (notes/app.md Content view): each lists its parts and
//! says when it fits.

use super::{ViewType, always, part, sample_collection, sample_main, sample_note};
use crate::store::Reader;
use osis::{Result, Tid};

/// A note: a title and a body.
pub static NOTE: ViewType = ViewType { id: "note", label: "Note", fits: Some(note_fits), parts: &[always("name"), always("body")], always_offered: false, custom: None, sample: sample_note, grow: None };

fn note_fits(cx: &Reader, t: Tid) -> Result<bool> {
    Ok(cx.applies("body", t)? || cx.applies("name", t)? || cx.aspects(t)?.is_empty())
}

/// A set of things.
pub static COLLECTION: ViewType = ViewType { id: "collection", label: "Collection", fits: Some(collection_fits), parts: &[always("name"), always("members")], always_offered: false, custom: None, sample: sample_collection, grow: Some(super::grow_tag) };

fn collection_fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("members", t)
}

/// The look a person chooses, on the thing holding that choice.
pub static LOOK: ViewType = ViewType { id: "look", label: "Look", fits: Some(look_fits), parts: &[always("look")], always_offered: true, custom: None, sample: sample_main, grow: None };

fn look_fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("look", t)
}

/// Every aspect from its schema type: reached from the context menu, or when nothing else fits.
pub static RAW: ViewType = ViewType { id: "raw", label: "All fields", fits: None, parts: &[always("name"), always("fields")], always_offered: false, custom: None, sample: sample_note, grow: None };

/// The opener's chrome below its content: places, Add, who can see it, change and undo.
pub static CHROME: ViewType = ViewType { id: "chrome", label: "Chrome", fits: None, parts: &[part("places"), part("add"), part("about")], always_offered: false, custom: None, sample: sample_note, grow: None };
