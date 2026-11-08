//! The opener's chrome below its content: places, Add, who can see it, change and undo.

use super::{Part, ViewType, part};

const PARTS: &[Part] = &[part("places"), part("add"), part("about")];

pub static CHROME: ViewType = ViewType { id: "chrome", label: "Chrome", fits: None, parts: PARTS, custom: None };
