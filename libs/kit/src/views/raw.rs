use super::{Part, ViewType, always};

const PARTS: &[Part] = &[always("name"), always("fields")];

/// Every aspect from its schema type: reached from the context menu, or when nothing else fits.
pub static RAW: ViewType = ViewType { id: "raw", label: "All fields", fits: None, parts: PARTS, always_offered: false, custom: None, sample: super::sample_note };
