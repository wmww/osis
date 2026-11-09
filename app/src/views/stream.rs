use osis_kit::views::{Part, ViewType, always};
use osis_kit::store::Reader;
use osis::{Result, Tid};

fn fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("log", t)
}

const PARTS: &[Part] = &[always("name"), always("log")];

pub static VIEW: ViewType = ViewType { id: "stream", label: "Stream", fits: Some(fits), parts: PARTS, always_offered: false, custom: None, sample: crate::facets::log::sample };
