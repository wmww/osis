#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! osis-kit's test binary.

mod gestures;
mod graph;
mod ime;
mod input;
mod layout;
mod list;
mod menu;
mod start;
mod tags;
mod theme;
mod view_tree;
mod view_costs;

use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::{NewWidget, Widget};
use std::sync::mpsc::{Receiver, channel};

/// A headless render root over `w`, `size` physical px at `scale`, and what its widgets signal.
pub(crate) fn render_root(w: NewWidget<dyn Widget>, (width, height): (u32, u32), scale: f64) -> (RenderRoot, Receiver<RenderRootSignal>) {
    let (tx, signals) = channel();
    let opts = RenderRootOptions {
        default_properties: std::sync::Arc::new(osis_kit::masonry::theme::default_property_set()),
        use_system_fonts: false,
        size_policy: WindowSizePolicy::User,
        size: osis_kit::masonry::dpi::PhysicalSize::new(width, height),
        scale_factor: scale,
        test_font: None,
    };
    (RenderRoot::new(w, move |s| drop(tx.send(s)), opts), signals)
}
