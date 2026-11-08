use osis_kit::views::{Part, ViewType, always};
use osis_kit::view::Cx;
use osis::{Result, Tid};

fn fits(cx: &Cx<'_>, t: Tid) -> Result<bool> {
    cx.applies("log", t)
}

const PARTS: &[Part] = &[always("name"), always("log")];

pub static VIEW: ViewType = ViewType { id: "stream", label: "Stream", fits: Some(fits), parts: PARTS, always_offered: false, custom: None };
