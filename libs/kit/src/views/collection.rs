use super::{Part, ViewType, always};
use crate::store::Reader;
use osis::{Result, Tid};

fn fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("members", t)
}

const PARTS: &[Part] = &[always("name"), always("members")];

pub static VIEW: ViewType = ViewType { id: "collection", label: "Collection", fits: Some(fits), parts: PARTS, always_offered: false, custom: None, sample: super::sample_collection };
