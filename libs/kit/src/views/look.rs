//! The look a person chooses, a content view of the thing holding that choice.
use super::{Part, ViewType, always};
use crate::store::Reader;
use osis::{Result, Tid};

fn fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("look", t)
}

const PARTS: &[Part] = &[always("look")];

pub static VIEW: ViewType = ViewType { id: "look", label: "Look", fits: Some(fits), parts: PARTS, always_offered: true, custom: None, sample: super::sample_main, grow: None };
