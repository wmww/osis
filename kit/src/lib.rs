//! osis-kit: the first-party UI toolkit over Masonry (notes/app.md, kit and app). Holds
//! windowing (`window`), the osis-Masonry driver pieces (`marshal`: watch callbacks onto the UI
//! thread; `list`: the keyed list reconciler), theme tokens (`theme`) and simple widgets
//! (`widgets`). It does not wrap the osis API, and does not abstract over Masonry: apps use
//! `osis_kit::masonry` (one pinned version) directly.
#![forbid(unsafe_code)]

pub mod list;
pub mod marshal;
pub mod theme;
pub mod widgets;
pub mod window;

pub use masonry;
pub use masonry_winit;
