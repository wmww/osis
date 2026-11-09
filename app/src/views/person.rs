use osis_kit::views::{Part, ViewType, always, part};
use osis_kit::store::Reader;
use osis::{Result, Tid};

fn fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("contact", t)
}

const PARTS: &[Part] = &[always("name"), part("contact"), always("body")];

pub static VIEW: ViewType = ViewType { id: "person", label: "Person", fits: Some(fits), parts: PARTS, always_offered: false, custom: None };
