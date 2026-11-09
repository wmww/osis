use super::{Part, ViewType, always};
use crate::store::Reader;
use osis::{Result, Tid};

fn fits(cx: &Reader, t: Tid) -> Result<bool> {
    Ok(cx.applies("body", t)? || cx.applies("name", t)? || cx.aspects(t)?.is_empty())
}

const PARTS: &[Part] = &[always("name"), always("body")];

pub static VIEW: ViewType = ViewType { id: "note", label: "Note", fits: Some(fits), parts: PARTS, always_offered: false, custom: None, sample: super::sample_note, grow: None };
