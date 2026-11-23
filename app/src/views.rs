//! The app's content views (notes/app.md Code shape).

use osis::{Result, Tid};
use osis_kit::store::Reader;
use osis_kit::views::{ViewType, always, part, sample_offer};

pub static EVENT: ViewType = ViewType { id: "event", label: "Event", fits: Some(event_fits), parts: &[always("name"), part("event-place"), part("event-time"), always("body")], always_offered: false, custom: None, sample: |d| sample_offer(d, "event"), grow: None };
fn event_fits(cx: &Reader, t: Tid) -> Result<bool> {
    Ok(cx.applies("event-time", t)? || cx.applies("event-place", t)?)
}

pub static PERSON: ViewType = ViewType { id: "person", label: "Person", fits: Some(person_fits), parts: &[always("name"), part("contact"), always("body")], always_offered: false, custom: None, sample: |d| sample_offer(d, "person"), grow: None };
fn person_fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("contact", t)
}

pub static STREAM: ViewType = ViewType { id: "stream", label: "Stream", fits: Some(stream_fits), parts: &[always("name"), always("log")], always_offered: false, custom: None, sample: crate::facets::log::sample, grow: Some(crate::facets::log::grow) };
fn stream_fits(cx: &Reader, t: Tid) -> Result<bool> {
    cx.applies("log", t)
}
