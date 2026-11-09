use osis_kit::views::{Part, ViewType, always, part};
use osis_kit::store::Reader;
use osis::{Result, Tid};

fn fits(cx: &Reader, t: Tid) -> Result<bool> {
    Ok(cx.applies("event-time", t)? || cx.applies("event-place", t)?)
}

const PARTS: &[Part] = &[always("name"), part("event-place"), part("event-time"), always("body")];

pub static VIEW: ViewType = ViewType { id: "event", label: "Event", fits: Some(fits), parts: PARTS, always_offered: false, custom: None, sample: |d| osis_kit::views::sample_offer(d, "event"), grow: None };
